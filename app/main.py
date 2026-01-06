from datetime import datetime
import sys, traceback, os
from fastapi import FastAPI, Header, Depends, Request, HTTPException, Query, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from . import db
from .models import RingIn, TrackerIn, TrackerPatch, BrickIn

@asynccontextmanager
async def lifespan(app: FastAPI):
    # no hard table checks yet; we’ll do that after AWS tables exist
    yield

app = FastAPI(title="AXIS API", version="v1", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv("AXIS_CORS_ORIGINS", "http://localhost:3000").split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def current_user(x_user_id: str | None = Header(default=None)):
    # V1: header-based user id for speed
    return (x_user_id or "dev-user").strip()

def current_tz(x_user_tz: str | None = Header(default=None, alias="x-user-tz")) -> str:
    # Browser timezone from client. Example: "America/Denver"
    # Keep it as a string; db.py will validate/fallback safely.
    tz = (x_user_tz or "").strip()
    return tz or "UTC"

@app.get("/health")
def health():
    return {"ok": True, "time": datetime.utcnow().isoformat()}

@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"error": "bad_request", "detail": str(exc)})

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    print("\n=== UNHANDLED EXCEPTION ===", file=sys.stderr)
    traceback.print_exc()
    return JSONResponse(status_code=500, content={"error": "internal_server_error"})

# ---------------- Rings ----------------
@app.get("/v1/rings")
def list_rings(user_id: str = Depends(current_user)):
    return db.list_rings(owner_id=user_id)

@app.post("/v1/ring")
def create_ring(data: RingIn, user_id: str = Depends(current_user)):
    try:
        return db.create_ring(owner_id=user_id, ring_id=data.ring_id, name=data.name)
    except ValueError as e:
        msg = str(e)
        if msg in ("ring_id_required", "invalid_ring_id_slug"):
            raise HTTPException(status_code=400, detail=msg)
        if msg == "ring_id_already_exists":
            raise HTTPException(status_code=409, detail=msg)
        if msg == "ring_name_already_exists":
            raise HTTPException(status_code=409, detail=msg)
        raise

# ---------------- Trackers ----------------
@app.get("/v1/trackers")
def list_trackers(
    ring_id: str = Query(..., description="Ring slug"),
    user_id: str = Depends(current_user),
):
    return db.list_trackers(owner_id=user_id, ring_id=ring_id.strip().lower())

@app.post("/v1/tracker")
def create_tracker(data: TrackerIn, user_id: str = Depends(current_user)):
    try:
        return db.create_tracker(owner_id=user_id, data=data.model_dump())
    except ValueError as e:
        msg = str(e)
        if msg == "ring_not_found":
            raise HTTPException(status_code=404, detail=msg)
        if msg in ("tracker_id_required", "invalid_tracker_id_slug"):
            raise HTTPException(status_code=400, detail=msg)
        if msg in ("tracker_id_already_exists", "tracker_name_already_exists"):
            raise HTTPException(status_code=409, detail=msg)
        raise

@app.patch("/v1/tracker/{tracker_id}")
def patch_tracker(tracker_id: str, patch: TrackerPatch, user_id: str = Depends(current_user)):
    try:
        return db.patch_tracker(owner_id=user_id, tracker_id=tracker_id, patch=patch.model_dump(exclude_unset=True))
    except ValueError as e:
        msg = str(e)
        if msg == "tracker_not_found":
            raise HTTPException(status_code=404, detail=msg)
        raise

# ---------------- Bricks ----------------
@app.post("/v1/brick")
def create_brick(
    data: BrickIn,
    user_id: str = Depends(current_user),
    tz: str = Depends(current_tz),
):
    try:
        ts_iso = data.ts.isoformat() if data.ts else None
        return db.create_brick(
            owner_id=user_id,
            tracker_id=data.tracker_id,
            kind=data.kind,
            payload=data.payload or {},
            ts_iso=ts_iso,
            tz_name=tz
        )
    except ValueError as e:
        msg = str(e)
        if msg in ("tracker_not_found",):
            raise HTTPException(status_code=404, detail=msg)
        if msg in ("brick_kind_mismatch", "number_value_required", "note_text_required"):
            raise HTTPException(status_code=400, detail=msg)
        raise

@app.get("/v1/bricks")
def list_bricks(
    tracker_id: str = Query(...),
    limit: int = Query(20, ge=1, le=200),
    user_id: str = Depends(current_user),
):
    return db.list_bricks(owner_id=user_id, tracker_id=tracker_id, limit=limit)

@app.get("/v1/tracker/{tracker_id}/bricks")
def get_tracker_bricks(
    tracker_id: str,
    days: int = Query(7, ge=1, le=31),
    user_id: str = Depends(current_user),
    tz: str = Depends(current_tz),
):
    items = db.list_bricks_last_days(owner_id=user_id, tracker_id=tracker_id, days=days, tz_name=tz)
    return {"tracker_id": tracker_id, "days": days, "items": items}

# ---------------- Contributions (Heatmap) ----------------
@app.get("/v1/dashboard/contrib")
def dashboard_contrib(
    days: int = Query(365, ge=7, le=730),
    user_id: str = Depends(current_user),
    tz: str = Depends(current_tz),
):
    # Returns counts per local day for a GitHub-style heatmap
    return db.dashboard_contrib(owner_id=user_id, days=days, tz_name=tz)

# ---------------- Dashboard ----------------
@app.get("/v1/dashboard/today")
def dashboard_today(
    user_id: str = Depends(current_user),
    tz: str = Depends(current_tz),
):
    return db.dashboard_today(owner_id=user_id, tz_name=tz)
