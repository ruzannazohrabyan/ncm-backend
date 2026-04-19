from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.routers import auth, devices, snapshots, alerts, discovery

app = FastAPI(
    title="Network Config Manager API",
    description="Manage, backup and monitor network device configurations",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Build origin list from env var.
# If CORS_ORIGINS is empty → allow all origins (wildcard).
# If set → allow only those exact origins and enable credentials.
_raw_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
_allow_origins = _raw_origins if _raw_origins else ["*"]
_allow_credentials = bool(_raw_origins)   # credentials only when origins are explicit

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

PREFIX = "/api/v1"

app.include_router(auth.router, prefix=PREFIX)
app.include_router(devices.router, prefix=PREFIX)
app.include_router(snapshots.router, prefix=PREFIX)
app.include_router(alerts.router, prefix=PREFIX)
app.include_router(discovery.router, prefix=PREFIX)


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok"}
