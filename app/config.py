import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulntracker.db")
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    # Safe local-development fallback; production deployments must inject this.
    SECRET_KEY = "local-development-only-change-me"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
NOTIFY_SERVICE_URL = os.getenv("NOTIFY_SERVICE_URL", "http://localhost:3001")
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
SHARE_TOKEN_TTL_HOURS = 24
