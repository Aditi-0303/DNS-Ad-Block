import asyncio
import json
import logging
from datetime import datetime
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app import models, schemas
from app.db import SessionLocal, init_db
from app.ml_engine import DomainAnalyzer
from app.pihole_client import PiHoleClient, PiHoleClientError, PiHoleSettings, normalize_query

app = FastAPI(title="AI DNS Analytics Command Center")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

analyzer = DomainAnalyzer()
active_websockets: list[WebSocket] = []
broadcast_lock = asyncio.Lock()
pihole_sync_lock = asyncio.Lock()
pihole_client: PiHoleClient | None = None
pihole_sync_task: asyncio.Task | None = None
logger = logging.getLogger(__name__)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
async def startup_event() -> None:
    init_db()
    global pihole_client, pihole_sync_task
    settings = PiHoleSettings.from_environment()
    if settings:
        pihole_client = PiHoleClient(settings)
        pihole_sync_task = asyncio.create_task(pihole_sync_loop())
        logger.info("Pi-hole synchronization is configured.")
    else:
        logger.info("Pi-hole synchronization is disabled; backend/.env is not configured.")


@app.on_event("shutdown")
async def shutdown_event() -> None:
    if pihole_sync_task:
        pihole_sync_task.cancel()


@app.get("/")
def root() -> dict:
    return {"status": "ok", "message": "AI DNS Analytics backend is running", "docs": "/docs"}


async def broadcast_new_log(payload: dict) -> None:
    async with broadcast_lock:
        stale: list[WebSocket] = []
        for websocket in active_websockets:
            try:
                await websocket.send_json(payload)
            except Exception:
                stale.append(websocket)
        for websocket in stale:
            active_websockets.remove(websocket)


def create_pihole_log(event: schemas.PiHoleEvent, db: Session, source_event_id: str | None = None) -> models.DNSLog:
    domain = event.domain.strip().lower().rstrip(".")
    explanation = analyzer.explain_pihole_event(
        domain=domain,
        blocked=event.blocked,
        matched_rule=event.matched_rule,
        list_source=event.list_source,
        request_count=event.request_count,
    )
    log = models.DNSLog(
        domain=domain,
        tld=domain.rsplit(".", 1)[-1] if "." in domain else "",
        prediction="blocked" if event.blocked else "allowed",
        score=round((1 - explanation["false_positive_score"]) * 100, 1),
        entropy=analyzer._calculate_entropy(domain),
        digit_count=sum(char.isdigit() for char in domain),
        domain_length=len(domain),
        explanation=explanation["block_reason"],
        shap_summary=json.dumps(explanation["evidence"]),
        source="pihole",
        source_event_id=source_event_id,
        client_ip=event.client_ip,
        query_type=event.query_type,
        is_blocked=event.blocked,
        category=explanation["category"],
        block_reason=explanation["block_reason"],
        matched_rule=event.matched_rule,
        list_source=event.list_source,
        evidence=json.dumps(explanation["evidence"]),
        false_positive_score=explanation["false_positive_score"],
        false_positive_risk=explanation["false_positive_risk"],
        impact_summary=explanation["impact_summary"],
        request_count=event.request_count,
        created_at=event.occurred_at or datetime.utcnow(),
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


async def synchronize_pihole_queries() -> dict[str, int]:
    if not pihole_client:
        raise PiHoleClientError("Pi-hole is not configured. Add PIHOLE_BASE_URL and PIHOLE_APP_PASSWORD to backend/.env.")
    async with pihole_sync_lock:
        queries = await asyncio.to_thread(pihole_client.fetch_queries)
        imported = 0
        skipped = 0
        db = SessionLocal()
        try:
            for raw_query in queries:
                normalized = normalize_query(raw_query)
                if not normalized:
                    skipped += 1
                    continue
                source_event_id = normalized.pop("source_event_id")
                if db.query(models.DNSLog.id).filter(models.DNSLog.source_event_id == source_event_id).first():
                    skipped += 1
                    continue
                try:
                    event = schemas.PiHoleEvent(**normalized)
                except ValueError:
                    skipped += 1
                    continue
                log = create_pihole_log(event, db, source_event_id)
                imported += 1
                await broadcast_new_log({
                    "id": log.id,
                    "domain": log.domain,
                    "blocked": log.is_blocked,
                    "category": log.category,
                    "explanation": log.explanation,
                    "created_at": log.created_at.isoformat(),
                })
        finally:
            db.close()
    return {"imported": imported, "skipped": skipped, "inspected": len(queries)}


async def pihole_sync_loop() -> None:
    while True:
        try:
            await synchronize_pihole_queries()
        except PiHoleClientError as error:
            logger.warning("Pi-hole synchronization failed: %s", error)
        except Exception:
            logger.exception("Unexpected Pi-hole synchronization failure")
        await asyncio.sleep(10)


@app.post("/analyze", response_model=schemas.AnalyzeResponse)
async def analyze_domain(request: schemas.AnalyzeRequest, db: Session = Depends(get_db)) -> dict:
    data = analyzer.analyze(request.domain)
    log = models.DNSLog(
        domain=data["domain"],
        tld=data["tld"],
        prediction=data["prediction"],
        score=data["score"],
        entropy=data["entropy"],
        digit_count=data["digit_count"],
        domain_length=data["domain_length"],
        explanation=data["explanation"],
        shap_summary=data["shap_summary"],
        source="api",
        client_ip=None,
        query_type="A",
        is_blocked=False,
        category="manual_lookup",
        block_reason="Manual domain lookup; no Pi-hole decision was provided.",
        evidence=data["shap_summary"],
        false_positive_score=0.0,
        false_positive_risk="low",
        impact_summary="No Pi-hole block impact is available for a manual lookup.",
        request_count=1,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    payload = {
        "id": log.id,
        "domain": log.domain,
        "prediction": log.prediction,
        "score": log.score,
        "created_at": log.created_at.isoformat(),
        "tld": log.tld,
        "explanation": log.explanation,
    }
    await broadcast_new_log(payload)
    return data


@app.post("/pihole/events", response_model=schemas.PiHoleEventResponse, status_code=201)
async def ingest_pihole_event(event: schemas.PiHoleEvent, db: Session = Depends(get_db)) -> dict:
    """Store a normalized Pi-hole event with traceable XAI evidence.

    A Raspberry Pi adapter should call this endpoint after reading Pi-hole's
    query log/API.  `blocked` is accepted as Pi-hole's decision and is never
    overwritten by the explainability layer.
    """
    log = create_pihole_log(event, db)
    explanation = {
        "category": log.category,
        "block_reason": log.block_reason,
        "matched_rule": log.matched_rule,
        "list_source": log.list_source,
        "evidence": json.loads(log.evidence),
        "false_positive_score": log.false_positive_score,
        "false_positive_risk": log.false_positive_risk,
        "impact_summary": log.impact_summary,
    }
    response = {"id": log.id, "domain": log.domain, "blocked": event.blocked, "explanation": explanation}
    await broadcast_new_log({**response, "created_at": log.created_at.isoformat()})
    return response


@app.post("/pihole/sync", response_model=schemas.PiHoleSyncResponse)
async def sync_pihole() -> dict:
    """Manually fetch the latest Pi-hole query-log entries now."""
    try:
        result = await synchronize_pihole_queries()
    except PiHoleClientError as error:
        from fastapi import HTTPException
        raise HTTPException(status_code=502, detail=str(error)) from error
    return {**result, "message": "Pi-hole query log synchronized."}


@app.get("/logs", response_model=list[schemas.DNSLogRead])
def read_logs(db: Session = Depends(get_db)) -> list[models.DNSLog]:
    logs = (
        db.query(models.DNSLog)
        .order_by(models.DNSLog.created_at.desc())
        .limit(50)
        .all()
    )
    return logs


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    active_websockets.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_websockets:
            active_websockets.remove(websocket)
