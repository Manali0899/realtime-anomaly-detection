# Real-Time Anomaly Detection

A streaming pipeline that spots suspicious activity in security telemetry as it happens: password brute-forcing, logins from two countries minutes apart, and unusually large data uploads.

Events flow through **Kafka**, a Python **detector** flags anomalies using rules and per-user statistical baselines, alerts are stored in **Postgres**, and a versioned **REST API** (FastAPI) serves them to dashboards or other services.

I built this to get hands-on with the pieces behind real security data platforms: partitioned event streams, stateful stream processing, delivery guarantees, and API design.

## Architecture

```mermaid
flowchart LR
    G[Event generator] -->|keyed by user_id| K[(Kafka<br/>security-events<br/>3 partitions)]
    K --> D[Detector<br/>consumer group]
    D -->|idempotent insert| P[(Postgres<br/>alerts)]
    P --> A[REST API<br/>/v1]
    A --> C[Dashboards /<br/>other services]
```

1. **Generator** produces ~20 events/sec of simulated login and web-proxy traffic for 50 users, and plants attacks at random. Each event carries a ground-truth `label` used only for evaluation.
2. **Kafka** stores events in a topic partitioned by `user_id`, so every user's events stay in order.
3. **Detector** consumes the stream, keeps per-user state, and raises alerts.
4. **Postgres** stores alerts, indexed for the API's query patterns.
5. **API** exposes alerts with filtering, cursor pagination and API-key auth.

## What it detects

| Rule | Method | Fires when |
|---|---|---|
| `brute_force` | Sliding time window | 10+ failed logins for one user within 60 seconds |
| `impossible_travel` | Distance / time between logins | Two successful logins imply travel faster than 1,000 km/h |
| `large_upload` | Per-user z-score baseline | Upload size is 4+ standard deviations above that user's normal |

## Key design decisions

- **Partition by `user_id`.** All of a user's events land on the same partition in order, so one detector instance can hold that user's state without coordination.
- **Event time, not processing time.** Windows use the timestamp inside each event, so results stay correct when the detector falls behind and catches up.
- **At-least-once delivery + idempotent writes.** Offsets are committed only after an alert is saved. A crash can replay an event, but a unique constraint on `(event_id, rule)` makes the replayed insert a no-op, so alerts are never lost or duplicated.
- **Baselines are protected from attacks.** Flagged events are never added to a user's baseline, so one huge upload can't raise the bar for the next one.
- **Bad messages don't stop the pipeline.** Malformed events are logged with their partition and offset and skipped.
- **Keyset (cursor) pagination.** Page boundaries stay stable while new alerts stream in, and queries use the index instead of scanning with `OFFSET`.

More detail, including alternatives I considered and how this would change at scale, is in [docs/design.md](docs/design.md).

## Results

In a local run, the detector saved 63 alerts across all three rules (23 brute force, 22 large upload, 18 impossible travel). Every alert I checked matched a planted attack; I didn't see any false positives.

An evaluation script that reports precision and recall per rule is next on the roadmap.

## Running it locally

**Requirements:** Docker Desktop and Python 3.12.

```bash
git clone https://github.com/Manali0899/realtime-anomaly-detection.git
cd realtime-anomaly-detection

python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

docker compose up -d
docker exec -it kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
  --create --topic security-events --partitions 3 --replication-factor 1
```

Then run each of these in its own terminal:

```bash
python -m uvicorn api.main:app --port 8000
python -m detector.consumer
python -m generator.producer
```

Open **http://localhost:8000/docs** for the interactive API docs. Click **Authorize** and use the key `dev-secret-key`.

## API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Liveness check, including database connectivity (no auth) |
| `GET` | `/v1/alerts` | List alerts. Filters: `user_id`, `rule`, `severity`, `since`. Paging: `limit`, `cursor` |
| `GET` | `/v1/alerts/{alert_id}` | A single alert |
| `GET` | `/v1/stats` | Alert counts per rule and severity |

All `/v1` endpoints require an `X-API-Key` header.

```bash
curl -s -H "X-API-Key: dev-secret-key" \
  "http://localhost:8000/v1/alerts?rule=large_upload&limit=2"
```

```json
{
  "items": [
    {
      "alert_id": "6f1c2a9e-8d4b-4f3e-9a1c-2b7e5d0c8f13",
      "detected_at": "2026-11-22T03:41:07.218Z",
      "event_timestamp": "2026-11-22T03:41:07.193Z",
      "user_id": "user_024",
      "rule": "large_upload",
      "severity": "critical",
      "details": "142.3 MB to exfil-drop.example (z-score 9870, user avg 25 KB)",
      "event_id": "d2a7b1c4-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
    }
  ],
  "next_cursor": "MjAyNi0xMS0yMlQwMzo0MTowNy4yMThafDZmMWMy..."
}
```

Pass `next_cursor` back as `cursor` to get the next page. It's `null` on the last page.

![Interactive API docs](docs/images/api-docs.png)

## Configuration

Defaults work for local development. Override them with environment variables (see `.env.example`):

| Variable | Default | Used by |
|---|---|---|
| `DATABASE_URL` | `postgresql://detector:detector@localhost:5433/anomalies` | detector, API |
| `API_KEY` | `dev-secret-key` | API |

## Project structure

```
generator/   simulated events and planted attacks, Kafka producer
detector/    detection logic, Kafka consumer, Postgres writer
api/         FastAPI app, auth, response models
db/          database schema
docs/        design doc and images
```

## Known limitations

- **Detector state lives in memory.** Restarting the detector loses failed-login windows and upload baselines, so there's a short cold-start period where large uploads aren't caught.
- **Single Kafka broker with replication factor 1.** Fine locally; production would use 3 replicas.
- **Overlapping brute-force bursts can produce two alerts** for the same user. Grouping related alerts into incidents would fix this.
- **One static API key.** A real deployment would issue per-client keys or use OAuth.

## Roadmap

- [ ] Evaluation script reporting precision and recall per rule
- [ ] Persist detector state in Redis so baselines survive restarts
- [ ] Correlate related alerts into incidents
- [ ] Prometheus + Grafana dashboards for throughput and consumer lag
- [ ] Load test and document the first bottleneck
- [ ] Isolation Forest model alongside the rules
- [ ] Move stream processing to Flink
- [ ] gRPC service for internal queries
- [ ] Deploy one component to GCP
