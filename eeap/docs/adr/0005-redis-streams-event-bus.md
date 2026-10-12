# ADR-0005: Redis Streams with transactional outbox as the event bus

- Status: Accepted
- Date: 2026-10-12

## Context

Pipeline stages react to each other's state changes (run completed → rescore; graph
updated → re-correlate). Redis is already required for caching, rate limiting and agent
job queues. Event volume is moderate (≤ thousands/second at peak during large runs).

## Decision

Use Redis Streams (`eeap.<domain>`) with consumer groups for asynchronous events, with:

- **Transactional outbox** per schema: state change + `event_outbox` row in one DB
  transaction; a relay publishes and marks rows.
- **Idempotent inbox** per consumer: `event_inbox(consumer_group, event_id)` written in the
  same transaction as the side effect.
- At-least-once delivery, `XAUTOCLAIM` for stuck messages, DLQ after 5 attempts.
- Claim-check pattern for payloads > 256 KiB (MinIO `data_ref`).

## Alternatives considered

- Kafka: superior durability/replay at scale, but heavy for T1 deployments.
- RabbitMQ: mature, but an extra stateful service with no clear advantage here.
- PostgreSQL LISTEN/NOTIFY only: not durable, no consumer groups.

## Consequences

- (+) No extra infrastructure; simple local development.
- (+) Outbox makes Redis loss recoverable (unpublished rows replayed).
- (−) Redis Streams retention is memory-bound → MAXLEN trimming; long-term replay comes from
  the database, not the bus.
- (−) Abstracted behind `EventBus` interface in `shared/utils` to allow a Kafka adapter in T3.
