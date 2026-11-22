# Design: Real-Time Anomaly Detection

**Status:** MVP implemented
**Author:** Manali Karankal

## 1. Context

Security platforms watch a constant stream of logins and network requests. Attacks show up as patterns across several events, not as a single bad record: ten failed logins in a minute, two logins on different continents, one upload far larger than a user's normal. Catching them quickly means processing events as a stream, holding state per user, and making results available to other systems through an API.

## 2. Goals and non-goals

**Goals**
- Detect three attack patterns within seconds of the event arriving
- Never lose an alert, even if the detector or database crashes
- Serve alerts through a stable, versioned, authenticated API
- Measure detection quality against known ground truth

**Non-goals (for now)**
- Multi-tenant isolation
- Horizontal scaling beyond a single machine
- Real production traffic (events are simulated)

## 3. Architecture

```
generator -> Kafka (security-events, 3 partitions) -> detector -> Postgres -> FastAPI
```

### Event schema

Every event shares these fields:

| Field | Type | Notes |
|---|---|---|
| `event_id` | UUID | Unique per event |
| `timestamp` | ISO-8601, UTC | Event time, used for all windows |
| `user_id` | string | Kafka message key |
| `event_type` | `login` \| `web_request` | |
| `src_ip`, `city`, `country`, `lat`, `lon` | | Where the request came from |
| `label` | string | Ground truth for evaluation only. The detector never reads it. |

`login` events add `status` (`success` / `failure`). `web_request` events add `dest_domain` and `bytes_out`.

### Alert schema

Stored in the `alerts` table: `alert_id`, `detected_at`, `event_timestamp`, `user_id`, `rule`, `severity`, `details`, `event_id`. A unique constraint on `(event_id, rule)` enforces one alert per event per rule.

## 4. Key decisions

### 4.1 Partition by `user_id`

**Decision:** Use `user_id` as the Kafka message key.

**Why:** Kafka only guarantees ordering within a partition. Every detection rule compares a user's event with that same user's earlier events, so all of one user's events need to arrive in order at the same consumer. Keying by user gives that for free, and the consumer group can scale up to one detector per partition without sharing state.

**Trade-off:** A single very active user (a "hot key") can overload one partition. At scale I'd monitor per-partition lag and consider splitting hot users by a secondary key for rules that don't need strict ordering.

### 4.2 Event time over processing time

**Decision:** All windows and travel-speed calculations use the timestamp inside the event.

**Why:** If the detector falls behind (a restart, a slow database), it processes old events quickly when it catches up. Using the current clock would make a burst spread over a minute look instantaneous, or the reverse. Event time keeps results the same regardless of when processing happens.

**Trade-off:** Out-of-order or late events aren't handled yet. A stream processor like Flink handles this with watermarks; that's part of the Flink migration on the roadmap.

### 4.3 At-least-once delivery with idempotent writes

**Decision:** Disable automatic offset storage. Store each message's offset only after it is fully processed and any alert is written. Make the alert insert idempotent with `ON CONFLICT (event_id, rule) DO NOTHING`.

**Why:** With automatic commits, Kafka can mark a message done before the alert is saved, so a crash loses the alert. Committing after the write means a crash can only cause a replay, and the unique constraint turns a replayed insert into a no-op.

**Alternatives considered:** Kafka transactions (exactly-once) only cover writes back into Kafka, not into Postgres, so they don't solve this case. Idempotent writes are simpler and give the same result.

**Failure behavior:** If Postgres is down, the insert raises and the detector stops instead of skipping events. On restart it resumes from the last stored offset.

### 4.4 Per-user baselines with Welford's algorithm

**Decision:** Track a running mean and standard deviation of `bytes_out` per user, updated one value at a time.

**Why:** Memory per user stays constant (three numbers) no matter how many events we see, and a per-user baseline catches uploads that are unusual for that person even if they'd look normal company-wide.

**Cold start:** No alerts until a user has 20 samples. This misses attacks on brand-new users; a fallback absolute threshold (for example, anything over 50 MB) would cover that gap.

**Baseline poisoning:** Flagged values are never added to the baseline. The same applies to impossible travel: a flagged login does not become the user's last known location, which also prevents a false alert when the user's next real login comes from home.

### 4.5 Keyset pagination

**Decision:** Paginate `/v1/alerts` with an opaque cursor encoding the last `(detected_at, alert_id)` seen.

**Why:** Alerts arrive continuously. With `OFFSET`, a new alert shifts every page, so clients see duplicates or miss items, and large offsets force Postgres to scan and discard rows. A cursor gives stable pages and uses the `(detected_at DESC)` index. `alert_id` breaks ties between alerts with the same timestamp.

### 4.6 API versioning and auth

All business endpoints live under `/v1`, so breaking changes can ship as `/v2` without affecting existing clients. Requests need an `X-API-Key` header, compared with `secrets.compare_digest` to avoid timing attacks. `/health` stays unauthenticated so load balancers and Kubernetes probes can use it.

## 5. Failure modes

| Failure | Behavior |
|---|---|
| Detector crashes | Events wait in Kafka (lag grows). On restart it resumes from the last stored offset. In-memory state is lost. |
| Postgres down | Detector stops on the next alert without storing that offset. API `/health` returns 503. |
| Malformed message | Logged with partition and offset, then skipped. |
| Duplicate delivery | Unique constraint ignores the second insert. |
| Kafka broker down | Producer buffers and retries; consumers wait. With one broker, data is at risk. |

## 6. What changes at real scale

- **Kafka:** 3+ brokers, replication factor 3, `min.insync.replicas=2`, and many more partitions sized to peak throughput.
- **State:** Move per-user state out of process memory into a store that survives restarts (Redis, or Flink's managed state with checkpoints).
- **Storage:** Keep Postgres for alerts, but send raw events to a columnar store (ClickHouse, BigQuery) for investigation and model training.
- **Observability:** Export events/sec, processing latency and consumer lag per partition to Prometheus, with alerts when lag keeps growing.
- **Backpressure:** Batch database writes and bound in-memory queues so a slow database slows consumption instead of exhausting memory.

## 7. Open questions

- What alert volume per user is too much for an analyst to act on, and should alerts be grouped into incidents before they reach the API?
- Which rules need strict per-user ordering, and which could run on a differently partitioned stream?
