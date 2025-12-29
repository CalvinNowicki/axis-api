from pydantic import BaseModel, Field
from typing import Optional, Literal, Any, Dict, List
from datetime import datetime

Kind = Literal["boolean", "number", "note"]

# ---------- Rings ----------
class RingIn(BaseModel):
    ring_id: str = Field(..., description="slug, e.g. fitness")
    name: str

class RingOut(RingIn):
    owner_id: str
    created_ts: str

# ---------- Trackers ----------
class TrackerIn(BaseModel):
    ring_id: str
    name: str
    kind: Kind = "boolean"
    # V1 can ignore cadence/targets for rings grid; keep room:
    cadence: Optional[str] = "daily"
    target: Optional[Dict[str, Any]] = None

class TrackerOut(TrackerIn):
    tracker_id: str
    owner_id: str
    created_ts: str
    active: bool = True

class TrackerPatch(BaseModel):
    name: Optional[str] = None
    active: Optional[bool] = None
    cadence: Optional[str] = None
    target: Optional[Dict[str, Any]] = None

# ---------- Bricks ----------
class BrickIn(BaseModel):
    tracker_id: str
    kind: Kind
    payload: Dict[str, Any] = {}

    # Optional client-provided ts (otherwise server uses now)
    ts: Optional[datetime] = None

class BrickOut(BrickIn):
    brick_id: str
    owner_id: str
    ts: str
