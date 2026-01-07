import os, re, uuid
from datetime import datetime, timezone, date, timedelta
from zoneinfo import ZoneInfo
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

import boto3
from boto3.dynamodb.conditions import Key
from botocore.config import Config
from botocore.exceptions import ClientError

from .settings import settings

from zoneinfo import ZoneInfo

_slug_re = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def today_utc_yyyymmdd() -> str:
    # Use UTC date to match how we derive brick.day from ISO timestamps (iso[:10])
    return datetime.now(timezone.utc).date().isoformat()

def _tzinfo(tz_name: str | None) -> ZoneInfo:
    """
    Resolve IANA tz name safely. Always returns a ZoneInfo.
    Falls back to UTC if invalid/missing.
    """
    name = (tz_name or "").strip()
    if not name:
        return ZoneInfo("UTC")
    try:
        return ZoneInfo(name)
    except Exception:
        return ZoneInfo("UTC")

def today_local_yyyymmdd(tz_name: str | None) -> str:
    tz = _tzinfo(tz_name)
    return datetime.now(tz).date().isoformat()

def day_from_ts_iso_in_tz(ts_iso: str, tz_name: str | None) -> str:
    """
    Convert an ISO timestamp to YYYY-MM-DD in the user's timezone.
    If ts_iso is naive, assume UTC (defensive).
    """
    tz = _tzinfo(tz_name)
    dt = datetime.fromisoformat(ts_iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(tz).date().isoformat()

def utc_iso_floor_local_days_ago(days_ago: int, tz_name: str | None) -> str:
    """
    Returns UTC ISO string for local midnight 'days_ago' days ago in tz_name.
    Example: days_ago=0 => today's local midnight converted to UTC ISO.
    """
    tz = _tzinfo(tz_name)
    local_day = datetime.now(tz).date() - timedelta(days=days_ago)
    local_midnight = datetime(local_day.year, local_day.month, local_day.day, 0, 0, 0, tzinfo=tz)
    utc_dt = local_midnight.astimezone(timezone.utc)
    return utc_dt.isoformat()

def _norm_name(s: str) -> str:
    # Case-insensitive uniqueness + whitespace normalization
    return " ".join((s or "").strip().lower().split())

def _title_from_slug(slug: str) -> str:
    return " ".join(w[:1].upper() + w[1:] for w in slug.split("-") if w)

def _ring_name_guard_key(name: str) -> str:
    return f"__ring_name__#{_norm_name(name)}"

def _tracker_name_guard_key(ring_id: str, name: str) -> str:
    return f"__trk_name__#{ring_id}#{_norm_name(name)}"

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

    # ✅ Guard rails live in same table; never return them as real rings
    rings = [
        i for i in items
        if not str(i.get("ring_id", "")).startswith("__ring_name__#")
        and i.get("type") != "ring_name_guard"
        and "name" in i
    ]
    return rings

def create_ring(owner_id: str, ring_id: str, name: str) -> Dict[str, Any]:
    if not ring_id:
        raise ValueError("ring_id_required")

    slug = ring_id.strip().lower()
    if not _slug_re.fullmatch(slug):
        raise ValueError("invalid_ring_id_slug")

    # Name cleanliness
    display = (name or "").strip()
    if not display:
        display = _title_from_slug(slug)

    name_key = _ring_name_guard_key(display)

    # Unique constraints + ring create must be atomic
    item = {
        "owner_id": owner_id,
        "ring_id": slug,
        "name": display,
        "created_ts": now_utc_iso(),
    }

    guard = {
        "owner_id": owner_id,
        "ring_id": name_key,          # same table, same PK
        "type": "ring_name_guard",
        "target_ring_id": slug,
        "created_ts": now_utc_iso(),
    }

    try:
        ddb.meta.client.transact_write_items(
            TransactItems=[
                {
                    "Put": {
                        "TableName": rings_tbl.name,
                        "Item": _to_ddb(item),
                        "ConditionExpression": "attribute_not_exists(owner_id) AND attribute_not_exists(ring_id)",
                    }
                },
                {
                    "Put": {
                        "TableName": rings_tbl.name,
                        "Item": _to_ddb(guard),
                        "ConditionExpression": "attribute_not_exists(owner_id) AND attribute_not_exists(ring_id)",
                    }
                },
            ]
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "TransactionCanceledException":
            # Either ring_id exists OR name guard exists. Detect which.
            if rings_tbl.get_item(Key={"owner_id": owner_id, "ring_id": slug}).get("Item"):
                raise ValueError("ring_id_already_exists")
            raise ValueError("ring_name_already_exists")
        raise

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
        items = [_from_ddb(i) for i in resp.get("Items", [])]
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ValidationException":
            scan = trackers_tbl.scan()
            items = [i for i in scan.get("Items", []) if i.get("owner_id") == owner_id and i.get("ring_id") == ring_id]
            items = [_from_ddb(i) for i in items]
        else:
            raise

    # ✅ Filter tracker-name guards (same-table trick)
    trackers = [
        i for i in items
        if not str(i.get("tracker_id", "")).startswith("__trk_name__#")
        and i.get("type") != "tracker_name_guard"
        and "name" in i
    ]
    return trackers

def create_tracker(owner_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    ring_id = (data.get("ring_id") or "").strip().lower()
    if not ring_id:
        raise ValueError("ring_id_required")

    # confirm ring exists
    ring = rings_tbl.get_item(Key={"owner_id": owner_id, "ring_id": ring_id}).get("Item")
    if not ring:
        raise ValueError("ring_not_found")

    # tracker_slug is required now (permanent id)
    tracker_slug = (data.get("tracker_id") or "").strip().lower()
    if not tracker_slug:
        raise ValueError("tracker_id_required")
    if not _slug_re.fullmatch(tracker_slug):
        raise ValueError("invalid_tracker_id_slug")

    # permanent, unique-within-ring PK
    tracker_id = f"{ring_id}#{tracker_slug}"

    # Display name: prefer provided name, else derive from slug
    display = (data.get("name") or "").strip()
    if not display:
        display = _title_from_slug(tracker_slug)

    # Unique name-per-ring guard
    name_guard_key = _tracker_name_guard_key(ring_id, display)

    item = {
        "owner_id": owner_id,
        "tracker_id": tracker_id,
        "tracker_slug": tracker_slug,
        "ring_id": ring_id,
        "name": display,
        "kind": data.get("kind", "boolean"),
        "cadence": data.get("cadence", "daily"),
        "target": data.get("target"),
        "active": True,
        "created_ts": now_utc_iso(),
    }
    if item.get("target") is None:
        item.pop("target", None)

    guard = {
        "owner_id": owner_id,
        "tracker_id": name_guard_key,   # same table, same PK
        "type": "tracker_name_guard",
        "ring_id": ring_id,
        "target_tracker_id": tracker_id,
        "created_ts": now_utc_iso(),
    }

    try:
        ddb.meta.client.transact_write_items(
            TransactItems=[
                {
                    "Put": {
                        "TableName": trackers_tbl.name,
                        "Item": _to_ddb(item),
                        "ConditionExpression": "attribute_not_exists(owner_id) AND attribute_not_exists(tracker_id)",
                    }
                },
                {
                    "Put": {
                        "TableName": trackers_tbl.name,
                        "Item": _to_ddb(guard),
                        "ConditionExpression": "attribute_not_exists(owner_id) AND attribute_not_exists(tracker_id)",
                    }
                },
            ]
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "TransactionCanceledException":
            # Either tracker_id exists OR name guard exists
            if trackers_tbl.get_item(Key={"owner_id": owner_id, "tracker_id": tracker_id}).get("Item"):
                raise ValueError("tracker_id_already_exists")
            raise ValueError("tracker_name_already_exists")
        raise

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
        new_name = nm.strip()

        # Enforce unique name-per-ring (case-insensitive), atomically
        ring_id = cur.get("ring_id")
        old_name = cur.get("name", "")
        old_guard = _tracker_name_guard_key(ring_id, old_name) if old_name else None
        new_guard = _tracker_name_guard_key(ring_id, new_name)

        if _norm_name(old_name) != _norm_name(new_name):
            # transact: put new guard (must not exist), update tracker, delete old guard
            transact = [
                {
                    "Put": {
                        "TableName": trackers_tbl.name,
                        "Item": _to_ddb({
                            "owner_id": owner_id,
                            "tracker_id": new_guard,
                            "type": "tracker_name_guard",
                            "ring_id": ring_id,
                            "target_tracker_id": cur["tracker_id"],
                            "created_ts": now_utc_iso(),
                        }),
                        "ConditionExpression": "attribute_not_exists(owner_id) AND attribute_not_exists(tracker_id)",
                    }
                },
                {
                    "Update": {
                        "TableName": trackers_tbl.name,
                        "Key": _to_ddb({"owner_id": owner_id, "tracker_id": tracker_id}),
                        "UpdateExpression": "SET #nm = :v",
                        "ExpressionAttributeNames": {"#nm": "name"},
                        "ExpressionAttributeValues": _to_ddb({":v": new_name}),
                    }
                },
            ]

            if old_guard:
                transact.append({
                    "Delete": {
                        "TableName": trackers_tbl.name,
                        "Key": _to_ddb({"owner_id": owner_id, "tracker_id": old_guard}),
                    }
                })

            try:
                ddb.meta.client.transact_write_items(TransactItems=transact)
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "TransactionCanceledException":
                    raise ValueError("tracker_name_already_exists")
                raise

            # refresh updated record
            cur2 = trackers_tbl.get_item(Key={"owner_id": owner_id, "tracker_id": tracker_id}).get("Item")
            return _from_ddb(cur2)

        # same normalized name; just set trimmed
        setfield("name", new_name)

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
def create_brick(
    owner_id: str,
    tracker_id: str,
    kind: str,
    payload: Dict[str, Any],
    ts_iso: Optional[str],
    tz_name: Optional[str] = None,
) -> Dict[str, Any]:
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
    day = day_from_ts_iso_in_tz(iso, tz_name)  # YYYY-MM-DD in user's tz

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

def iso_utc_floor_days_ago(days_ago: int) -> str:
    d = datetime.now(timezone.utc).date() - timedelta(days=days_ago)
    # start of that day in UTC
    return datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=timezone.utc).isoformat()

def list_bricks_last_days(
    owner_id: str,
    tracker_id: str,
    days: int = 7,
    limit: int = 300,
    tz_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    days = max(1, min(int(days or 7), 31))          # guard rails
    limit = max(1, min(int(limit or 300), 500))     # guard rails

    end_iso = now_utc_iso()
    # include today as day 0, based on LOCAL midnight boundaries converted to UTC
    start_iso = utc_iso_floor_local_days_ago(days - 1, tz_name)

    resp = bricks_tbl.query(
        KeyConditionExpression=Key("tracker_id").eq(tracker_id) & Key("ts").between(start_iso, end_iso),
        ScanIndexForward=False,  # newest first
        Limit=limit,
    )

    items = [_from_ddb(i) for i in resp.get("Items", [])]
    return [i for i in items if i.get("owner_id") == owner_id]

# ------------------------
# Dashboard
# ------------------------
def dashboard_today(owner_id: str, tz_name: Optional[str] = None) -> Dict[str, Any]:
    rings = list_rings(owner_id)
    ring_ids = [r["ring_id"] for r in rings]

    # For V1 simplicity: list trackers ring-by-ring and compute completion by "any brick today".
    # This is good for ~20 trackers. Later we can optimize with precomputed stats.
    today = today_local_yyyymmdd(tz_name)

    ring_summaries = []
    for r in rings:
        if not r.get("ring_id") or not r.get("name"):
            continue
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
                b_day_local = day_from_ts_iso_in_tz(b.get("ts", ""), tz_name)
                done_today = (b_day_local == today) and (b.get("owner_id") == owner_id)
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


# ------------------------
# Contribution Heatmap
# ------------------------
def _safe_tz(tz_name: str) -> ZoneInfo:
    try:
        return ZoneInfo((tz_name or "UTC").strip())
    except Exception:
        return ZoneInfo("UTC")

def _iso_to_local_day(iso_ts: str, tz: ZoneInfo) -> str:
    # iso_ts like "2026-01-04T20:01:37.750215+00:00"
    # Convert to tz and return YYYY-MM-DD
    dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(tz).date().isoformat()

def dashboard_contrib(owner_id: str, days: int = 365, tz_name: str = "UTC") -> Dict[str, Any]:
    days = max(7, min(int(days or 365), 730))
    tz = _safe_tz(tz_name)

    # We'll include "today" in the window
    now_utc = datetime.now(timezone.utc)
    start_utc = now_utc - timedelta(days=days - 1)

    # Local "today" is based on tz
    today_local = now_utc.astimezone(tz).date()
    start_local = today_local - timedelta(days=days - 1)

    # Build active tracker universe once, but keep created day for day-specific denominators
    # tracker_id -> created_local_day (YYYY-MM-DD)
    tracker_created_day: Dict[str, str] = {}

    rings = list_rings(owner_id)
    for r in rings:
        ring_id = r.get("ring_id")
        if not ring_id:
            continue

        trackers = list_trackers(owner_id, ring_id)
        for t in trackers:
            if not t.get("active", True):
                continue
            trk_id = t.get("tracker_id")
            if not trk_id:
                continue

            created_ts = t.get("created_ts")
            if created_ts:
                created_local = _iso_to_local_day(created_ts, tz)
            else:
                # fallback: if missing, treat as eligible for the whole window
                created_local = start_local.isoformat()

            tracker_created_day[trk_id] = created_local

    # de-dupe + stable order
    active_tracker_ids = sorted(tracker_created_day.keys())
    total_active = len(active_tracker_ids)  # still useful as "current active"

    # Track distinct tracker completions by LOCAL day
    # day -> set(tracker_id)
    done_by_day: Dict[str, set] = {}

    for trk_id in active_tracker_ids:
        # Query bricks for this tracker within UTC window
        resp = bricks_tbl.query(
            KeyConditionExpression=Key("tracker_id").eq(trk_id)
            & Key("ts").between(start_utc.isoformat(), now_utc.isoformat()),
            ScanIndexForward=True,  # older -> newer (doesn't really matter)
            Limit=500,              # guard rail per tracker
        )
        items = [_from_ddb(i) for i in resp.get("Items", [])]

        for b in items:
            if b.get("owner_id") != owner_id:
                continue
            ts = b.get("ts")
            if not ts:
                continue

            day_local = _iso_to_local_day(ts, tz)

            # If the tracker didn't exist yet on that local day, ignore it
            created_local = tracker_created_day.get(trk_id)
            if created_local and date.fromisoformat(day_local) < date.fromisoformat(created_local):
                continue

            # extra safety: ensure within the local window we emit
            d_date = date.fromisoformat(day_local)
            if d_date < start_local or d_date > today_local:
                continue

            s = done_by_day.get(day_local)
            if s is None:
                s = set()
                done_by_day[day_local] = s
            s.add(trk_id)

    # Emit dense list for the last N days (so UI can render blanks)
    # Denominator is day-specific: only trackers created on/before that local day
    series = []
    for i in range(days):
        d = (today_local - timedelta(days=(days - 1 - i))).isoformat()
        d_date = date.fromisoformat(d)

        total_that_day = sum(
            1 for _, cday in tracker_created_day.items()
            if date.fromisoformat(cday) <= d_date
        )

        done = len(done_by_day.get(d, set()))
        pct = (done / total_that_day) if total_that_day else 0.0

        series.append({
            "day": d,
            "done": done,
            "total": total_that_day,
            "percent": pct,  # 0..1
        })

    # total percent across the window isn't super meaningful; keep something simple:
    avg_percent = (sum(x["percent"] for x in series) / days) if days else 0.0

    return {
        "days": days,
        "total_active": total_active,
        "avg_percent": avg_percent,
        "items": series,
        "tz": str(tz),
    }