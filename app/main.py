from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth, devices, snapshots, alerts, discovery

app = FastAPI(
    title="Network Config Manager API",
    description="Manage, backup and monitor network device configurations",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
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
