from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def search_scans_by_query(db, query: str, owner_id: int) -> list:
    pattern = f"%{query}%"
    stmt = text("""SELECT id, title, description, severity, status, cve_id,
        affected_component, owner_id, created_at FROM scan_results
        WHERE owner_id = :owner_id AND (title LIKE :pattern OR description LIKE :pattern OR cve_id LIKE :pattern)""")
    return [dict(row._mapping) for row in db.execute(stmt, {"owner_id": owner_id, "pattern": pattern})]
