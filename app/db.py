import os, re, uuid
from datetime import datetime, timezone, date
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

import boto3
from boto3.dynamodb.conditions import Key
from botocore.config import Config
from botocore.exceptions import ClientError

from .settings import settings

_slug_re = re.compile(r"^[a-z0-9-]+$")

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def today_utc_yyyymmdd() -> str:
    # Use UTC date to match how we derive brick.day from ISO timestamps (iso[:10])
    return datetime.now(timezone.utc).date().isoformat()

def _to_ddb(val: Any) -> Any:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return Decimal(str(val))
    if isinstance(val, dict):
        return {k: _to_ddb(v) for k, v in val.items() if v is not None}
    if isinstance(val, list):
        return [_to_ddb(v) for v in val]
    return val

def _from_ddb(val: Any) -> Any:
    if isinstance(val, list):
        return [_from_ddb(v) for v in val]
    if isinstance(val, dict):
        return {k: _from_ddb(v) for k, v in val.items()}
    if isinstance(val, Decimal):
        return int(val) if val % 1 == 0 else float(val)
    return val

ddb = boto3.resource(
    "dynamodb",
    region_name=settings.aws_region,
    config=Config(retries={"max_attempts": 3}),
)

rings_tbl    = ddb.Table(settings.table_rings)
trackers_tbl = ddb.Table(settings.table_trackers)
bricks_tbl   = ddb.Table(settings.table_bricks)

# ------------------------
# Rings
# ------------------------
def list_rings(owner_id: str) -> List[Dict[str, Any]]:
    resp = rings_tbl.query(
        KeyConditionExpression=Key("owner_id").eq(owner_id),
        ScanIndexForward=True,
    )
    items = [_from_ddb(i) for i in resp.get("Items", [])]
    return items

def create_ring(owner_id: str, ring_id: str, name: str) -> Dict[str, Any]:
    if not ring_id:
        raise ValueError("ring_id_required")
    slug = ring_id.strip().lower()
    if not _slug_re.fullmatch(slug):
        raise ValueError("invalid_ring_id_slug")

    existing = rings_tbl.get_item(Key={"owner_id": owner_id, "ring_id": slug}).get("Item")
    if existing:
        raise ValueError("ring_id_already_exists")

    item = {
        "owner_id": owner_id,
        "ring_id": slug,
        "name": name.strip() or slug.capitalize(),
        "created_ts": now_utc_iso(),
    }
    rings_tbl.put_item(Item=_to_ddb(item))
    return item

# ------------------------
# Trackers
# ------------------------
def list_trackers(owner_id: str, ring_id: str) -> List[Dict[str, Any]]:
    # Trackers table PK = owner_id, SK = tracker_id
    # GSI: ring_owner_idx (ring_id, owner_id)
    try:
        resp = trackers_tbl.query(
            IndexName="ring_owner_idx",
            KeyConditionExpression=Key("ring_id").eq(ring_id) & Key("owner_id").eq(owner_id),
            ScanIndexForward=True,
        )
        return [_from_ddb(i) for i in resp.get("Items", [])]
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ValidationException":
            # Safety fallback while index is being created
            scan = trackers_tbl.scan()
            items = [i for i in scan.get("Items", []) if i.get("owner_id") == owner_id and i.get("ring_id") == ring_id]
            return [_from_ddb(i) for i in items]
        raise

def create_tracker(owner_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    ring_id = data["ring_id"].strip().lower()

    # confirm ring exists
    ring = rings_tbl.get_item(Key={"owner_id": owner_id, "ring_id": ring_id}).get("Item")
    if not ring:
        raise ValueError("ring_not_found")

    tracker_id = str(uuid.uuid4())
    item = {
        "owner_id": owner_id,
        "tracker_id": tracker_id,
        "ring_id": ring_id,
        "name": data["name"].strip(),
        "kind": data.get("kind", "boolean"),
        "cadence": data.get("cadence", "daily"),
        "target": data.get("target"),
        "active": True,
        "created_ts": now_utc_iso(),
    }
    # remove nulls
    if item.get("target") is None:
        item.pop("target", None)

    trackers_tbl.put_item(Item=_to_ddb(item))
    return item

def patch_tracker(owner_id: str, tracker_id: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    # read
    cur = trackers_tbl.get_item(Key={"owner_id": owner_id, "tracker_id": tracker_id}).get("Item")
    if not cur:
        raise ValueError("tracker_not_found")

    allowed = {"name", "active", "cadence", "target"}
    unknown = set(patch.keys()) - allowed
    if unknown:
        raise ValueError(f"invalid_fields: {', '.join(sorted(unknown))}")

    set_exprs, remove_exprs = [], []
    expr_vals, expr_names = {}, {}

    def setfield(key: str, val: Any):
        kn = f"#f_{key}"
        vn = f":v_{key}"
        expr_names[kn] = key
        expr_vals[vn] = _to_ddb(val)
        set_exprs.append(f"{kn} = {vn}")

    def removefield(key: str):
        kn = f"#f_{key}"
        expr_names[kn] = key
        remove_exprs.append(kn)

    if "name" in patch:
        nm = patch["name"]
        if not isinstance(nm, str) or not nm.strip():
            raise ValueError("invalid_name")
        setfield("name", nm.strip())

    if "active" in patch:
        setfield("active", bool(patch["active"]))

    if "cadence" in patch:
        setfield("cadence", str(patch["cadence"]).strip().lower())

    if "target" in patch:
        if patch["target"] is None:
            removefield("target")
        else:
            setfield("target", patch["target"])

    if not set_exprs and not remove_exprs:
        return _from_ddb(cur)

    parts = []
    if set_exprs:
        parts.append("SET " + ", ".join(set_exprs))
    if remove_exprs:
        parts.append("REMOVE " + ", ".join(remove_exprs))

    resp = trackers_tbl.update_item(
        Key={"owner_id": owner_id, "tracker_id": tracker_id},
        UpdateExpression=" ".join(parts),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_vals if expr_vals else None,
        ReturnValues="ALL_NEW",
    )
    return _from_ddb(resp["Attributes"])

# ------------------------
# Bricks
# ------------------------
def create_brick(owner_id: str, tracker_id: str, kind: str, payload: Dict[str, Any], ts_iso: Optional[str]) -> Dict[str, Any]:
    tracker = trackers_tbl.get_item(Key={"owner_id": owner_id, "tracker_id": tracker_id}).get("Item")
    if not tracker:
        raise ValueError("tracker_not_found")

    if kind != tracker.get("kind"):
        raise ValueError("brick_kind_mismatch")

    # minimal validation
    if kind == "number":
        if "value" not in payload:
            raise ValueError("number_value_required")
        float(payload["value"])  # will raise if invalid
    if kind == "note":
        txt = payload.get("text", "")
        if not isinstance(txt, str) or not txt.strip():
            raise ValueError("note_text_required")
        payload["text"] = txt.strip()

    iso = ts_iso or now_utc_iso()
    day = iso[:10]  # YYYY-MM-DD (UTC ISO prefix)

    item = {
        "owner_id": owner_id,
        "tracker_id": tracker_id,
        "ts": iso,
        "day": day,
        "brick_id": str(uuid.uuid4()),
        "kind": kind,
        "payload": payload or {},
    }
    # PK on bricks table is tracker_id, sort key ts, but we also store owner_id for security checks.
    bricks_tbl.put_item(Item=_to_ddb(item))
    return item

def list_bricks(owner_id: str, tracker_id: str, limit: int = 20) -> List[Dict[str, Any]]:
    resp = bricks_tbl.query(
        KeyConditionExpression=Key("tracker_id").eq(tracker_id),
        ScanIndexForward=False,
        Limit=max(1, min(limit, 200)),
    )
    items = [_from_ddb(i) for i in resp.get("Items", [])]
    # security: only return those owned by this user
    return [i for i in items if i.get("owner_id") == owner_id]

# ------------------------
# Dashboard
# ------------------------
def dashboard_today(owner_id: str) -> Dict[str, Any]:
    rings = list_rings(owner_id)
    ring_ids = [r["ring_id"] for r in rings]

    # For V1 simplicity: list trackers ring-by-ring and compute completion by "any brick today".
    # This is good for ~20 trackers. Later we can optimize with precomputed stats.
    today = today_utc_yyyymmdd()

    ring_summaries = []
    for r in rings:
        trackers = list_trackers(owner_id, r["ring_id"])
        active = [t for t in trackers if t.get("active", True)]
        total = len(active)
        done = 0

        # mark doneToday by fetching latest brick and checking day
        tracker_states = []
        for t in active:
            bricks = bricks_tbl.query(
                KeyConditionExpression=Key("tracker_id").eq(t["tracker_id"]),
                ScanIndexForward=False,
                Limit=1,
            ).get("Items", [])
            done_today = False
            if bricks:
                b = _from_ddb(bricks[0])
                done_today = (b.get("day") == today) and (b.get("owner_id") == owner_id)
            if done_today:
                done += 1
            tracker_states.append({
                "tracker_id": t["tracker_id"],
                "name": t["name"],
                "kind": t["kind"],
                "doneToday": done_today,
            })

        ring_summaries.append({
            "ring_id": r["ring_id"],
            "name": r["name"],
            "done": done,
            "total": total,
            "percent": (done / total) if total else 0.0,
            "trackers": tracker_states,
        })

    return {
        "date": today,
        "rings": ring_summaries,
    }
