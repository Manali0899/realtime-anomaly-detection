import base64
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query

from api.auth import require_api_key
from api.db import pool
from api.models import Alert, AlertPage, Rule, RuleCount, Severity


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Runs once at startup and once at shutdown
    pool.open()
    yield
    pool.close()


app = FastAPI(
    title="Realtime Anomaly Detection API",
    description="Query security alerts produced by the streaming detector.",
    version="1.0.0",
    lifespan=lifespan,
)

# Every route on this router lives under /v1 and requires an API key
v1 = APIRouter(prefix="/v1", dependencies=[Depends(require_api_key)])


def encode_cursor(detected_at: datetime, alert_id: UUID) -> str:
    # The cursor = "where the last page ended", packed into a URL-safe string
    raw = f"{detected_at.isoformat()}|{alert_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        timestamp, alert_id = raw.split("|")
        return datetime.fromisoformat(timestamp), UUID(alert_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid cursor")


@app.get("/health", tags=["health"])
def health():
    try:
        with pool.connection(timeout=2.0) as conn:
            conn.execute("SELECT 1")
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return {"status": "ok"}


@v1.get("/alerts", response_model=AlertPage, tags=["alerts"])
def list_alerts(
    user_id: str | None = None,
    rule: Rule | None = None,
    severity: Severity | None = None,
    since: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: str | None = None,
):
    # Build the WHERE clause from fixed SQL pieces. User values only ever go
    # into params (the %s placeholders), never into the SQL text: no SQL injection.
    conditions = []
    params = []

    if user_id:
        conditions.append("user_id = %s")
        params.append(user_id)
    if rule:
        conditions.append("rule = %s")
        params.append(rule)
    if severity:
        conditions.append("severity = %s")
        params.append(severity)
    if since:
        conditions.append("detected_at >= %s")
        params.append(since)
    if cursor:
        # Keyset pagination: "give me alerts older than the last one I saw"
        cursor_time, cursor_id = decode_cursor(cursor)
        conditions.append("(detected_at, alert_id) < (%s, %s)")
        params.extend([cursor_time, cursor_id])

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"""
        SELECT * FROM alerts
        {where}
        ORDER BY detected_at DESC, alert_id DESC
        LIMIT %s
    """
    # Ask for one extra row: if it comes back, there's another page
    params.append(limit + 1)

    with pool.connection() as conn:
        rows = conn.execute(query, params).fetchall()

    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = None
    if has_more:
        next_cursor = encode_cursor(rows[-1]["detected_at"], rows[-1]["alert_id"])

    return AlertPage(items=rows, next_cursor=next_cursor)


@v1.get("/alerts/{alert_id}", response_model=Alert, tags=["alerts"])
def get_alert(alert_id: UUID):
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE alert_id = %s", [alert_id]
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return row


@v1.get("/stats", response_model=list[RuleCount], tags=["stats"])
def alert_stats(since: datetime | None = None):
    query = "SELECT rule, severity, COUNT(*) AS count FROM alerts"
    params = []
    if since:
        query += " WHERE detected_at >= %s"
        params.append(since)
    query += " GROUP BY rule, severity ORDER BY count DESC"

    with pool.connection() as conn:
        return conn.execute(query, params).fetchall()


# Must come AFTER the routes above are defined
app.include_router(v1)
