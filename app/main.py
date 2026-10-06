import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from typing import List, Optional

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import models
from auth import create_access_token, get_current_user, get_password_hash, verify_password
from config import ALLOWED_ORIGINS, NOTIFY_SERVICE_URL, SHARE_TOKEN_TTL_HOURS
from database import engine, get_db, search_scans_by_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
models.Base.metadata.create_all(bind=engine)
app = FastAPI(title="VulnTracker API", version="1.1.0")
if ALLOWED_ORIGINS:
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"])

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=3, max_length=100)
    # The prototype accepts legacy starter users; production should enforce a stronger policy.
    password: str = Field(min_length=1, max_length=128)
class UserLogin(BaseModel):
    username: str
    password: str
class UserOut(BaseModel):
    id: int; username: str; email: str; created_at: datetime
    class Config: from_attributes = True
class ScanCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=10000)
    severity: str = "medium"
    cve_id: Optional[str] = Field(default=None, max_length=30)
    affected_component: str = Field(min_length=1, max_length=200)
    remediation_notes: Optional[str] = Field(default=None, max_length=10000)
class ScanUpdate(BaseModel):
    status: Optional[str] = None
    remediation_notes: Optional[str] = Field(default=None, max_length=10000)
class ShareRequest(BaseModel):
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)
class ScanOut(BaseModel):
    id: int; title: str; description: Optional[str]; severity: str; status: str; cve_id: Optional[str]; affected_component: str; remediation_notes: Optional[str]; owner_id: int; created_at: datetime
    class Config: from_attributes = True

def _fire_notify(event: str, payload: dict) -> None:
    try:
        httpx.post(f"{NOTIFY_SERVICE_URL}/notify", json={"event": event, "payload": payload}, timeout=5.0)
    except httpx.HTTPError as exc:
        logger.warning("Notification service unavailable: %s", exc)

def _scan_for_owner(db, scan_id, user_id):
    scan = db.query(models.ScanResult).filter(models.ScanResult.id == scan_id, models.ScanResult.owner_id == user_id).first()
    if not scan: raise HTTPException(status_code=404, detail="Scan not found")
    return scan

def _token_hash(token: str) -> str: return hashlib.sha256(token.encode()).hexdigest()

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter((models.User.username == payload.username) | (models.User.email == payload.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already registered")
    user = models.User(username=payload.username, email=payload.email, hashed_password=get_password_hash(payload.password))
    db.add(user); db.commit(); db.refresh(user); return user

@app.post("/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    return {"access_token": create_access_token({"sub": user.username}), "token_type": "bearer"}

@app.get("/scans", response_model=List[ScanOut])
def list_scans(skip: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100), db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    return db.query(models.ScanResult).filter(models.ScanResult.owner_id == current_user.id).offset(skip).limit(limit).all()

@app.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(payload: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    if payload.severity not in ("critical", "high", "medium", "low"): raise HTTPException(400, "Invalid severity")
    scan = models.ScanResult(**payload.model_dump(), owner_id=current_user.id); db.add(scan); db.commit(); db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.created", {"id": scan.id, "title": scan.title, "severity": scan.severity})
    return scan

@app.get("/scans/search")
def search_scans(q: str = Query(min_length=2, max_length=100), db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    results = search_scans_by_query(db, q, current_user.id); return {"results": results, "count": len(results)}

@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)): return _scan_for_owner(db, scan_id, current_user.id)

@app.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(scan_id: int, payload: ScanUpdate, background_tasks: BackgroundTasks, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    scan = _scan_for_owner(db, scan_id, current_user.id)
    if payload.status is not None:
        if payload.status not in ("open", "in_progress", "resolved"): raise HTTPException(400, "Invalid status")
        scan.status = payload.status
    if payload.remediation_notes is not None: scan.remediation_notes = payload.remediation_notes
    db.commit(); db.refresh(scan); background_tasks.add_task(_fire_notify, "scan.updated", {"id": scan.id, "status": scan.status}); return scan

@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    db.delete(_scan_for_owner(db, scan_id, current_user.id)); db.commit()

@app.post("/scans/{scan_id}/share")
def create_share(scan_id: int, payload: ShareRequest, request: Request, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    _scan_for_owner(db, scan_id, current_user.id)
    raw_token = secrets.token_urlsafe(32)
    link = models.ShareLink(token_hash=_token_hash(raw_token), scan_id=scan_id, expires_at=datetime.utcnow() + timedelta(hours=SHARE_TOKEN_TTL_HOURS), password_hash=get_password_hash(payload.password) if payload.password else None)
    db.add(link); db.commit()
    return {"share_url": str(request.base_url).rstrip("/") + "/share/" + raw_token, "expires_at": link.expires_at}

@app.get("/share/{token}", response_model=ScanOut)
def read_shared_scan(token: str, password: Optional[str] = None, db: Session = Depends(get_db)):
    link = db.query(models.ShareLink).filter(models.ShareLink.token_hash == _token_hash(token)).first()
    if not link or link.expires_at <= datetime.utcnow(): raise HTTPException(status_code=404, detail="Share link not found or expired")
    if link.password_hash and (not password or not verify_password(password, link.password_hash)): raise HTTPException(status_code=401, detail="Password required or incorrect")
    return link.scan

@app.get("/health")
def health(): return {"status": "ok", "service": "vulntracker-api"}
