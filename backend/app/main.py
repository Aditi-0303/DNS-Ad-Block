import asyncio
import json
from datetime import datetime
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app import models, schemas
from app.db import SessionLocal, init_db
from app.ml_engine import DomainAnalyzer

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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
async def startup_event() -> None:
    init_db()


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
    response = {"id": log.id, "domain": domain, "blocked": event.blocked, "explanation": explanation}
    await broadcast_new_log({**response, "created_at": log.created_at.isoformat()})
    return response


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
