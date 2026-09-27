# AI-Powered DNS Analytics Dashboard

This workspace contains a FastAPI backend and a Next.js frontend for a real-time AI-powered DNS analytics dashboard.

## Backend
- `backend/app/main.py` - FastAPI app with Pi-hole event ingestion, logs, and WebSocket updates
- `backend/app/ml_engine.py` - transparent Pi-hole explanation and false-positive assessment
- `backend/app/models.py` - SQLite model that stores the Pi-hole decision plus its evidence
- `backend/app/db.py` - SQLite database setup

### Run backend
```bash
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Frontend
- `frontend/app/page.tsx` - Futuristic command center UI
- `frontend/components/` - reusable metrics, chart, logs, and badge components
- `frontend/globals.css` - dark neon styles with Tailwind utility overrides

### Run frontend
```bash
cd frontend
npm install
npm run dev
```

## Notes
- WebSocket events stream new DNS logs to the dashboard at `ws://localhost:8000/ws`
- Pi-hole remains the source of truth: the XAI layer never changes a block/allow decision.

## Pi-hole event integration

Configure the local backend to poll a Pi-hole v6 instance by copying
`backend/.env.example` to `backend/.env` and setting the Pi-hole URL and
application password. The `.env` file is ignored by Git and must never be
committed.

```env
PIHOLE_BASE_URL=http://your-pihole-ip
PIHOLE_APP_PASSWORD=your-private-application-password
PIHOLE_VERIFY_TLS=false
```

The backend authenticates using Pi-hole's short-lived session ID and checks the
query log every 10 seconds. Use `POST /pihole/sync` to request an immediate
read-only sync. It ignores already imported query IDs.

For test data or a future Raspberry Pi-side adapter, send normalized events to
`POST /pihole/events`.

```json
{
  "domain": "googleads.g.doubleclick.net",
  "blocked": true,
  "client_ip": "192.168.1.25",
  "query_type": "A",
  "matched_rule": "||doubleclick.net^",
  "list_source": "EasyList",
  "request_count": 126
}
```

The API stores the original decision and returns an auditable explanation:
the matching rule/list, traffic category, evidence items, estimated impact, and
a low/medium/high false-positive risk. A high risk is a prompt for review, not
an automatic allow-list action.
