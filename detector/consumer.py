import json

from confluent_kafka import Consumer

from detector.detector import Detector
from detector.storage import AlertStore

TOPIC = "security-events"


def main():
    consumer = Consumer({
        "bootstrap.servers": "localhost:9092",
        "group.id": "anomaly-detector",
        "auto.offset.reset": "earliest",
        # Don't mark messages as done automatically. We do it ourselves after saving.
        "enable.auto.offset.store": False,
    })
    consumer.subscribe([TOPIC])
    detector = Detector()
    store = AlertStore()
    processed = skipped = alerts = 0

    print(f"Listening on '{TOPIC}', saving alerts to Postgres. Ctrl+C to stop.")
    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                print(f"Kafka error: {msg.error()}")
                continue

            try:
                event = json.loads(msg.value())
                alert = detector.process(event)
            except (ValueError, KeyError, TypeError) as err:
                skipped += 1
                print(f"Skipping bad message (partition {msg.partition()}, offset {msg.offset()}): {err!r}")
                consumer.store_offsets(message=msg)
                continue

            if alert:
                # If Postgres is down, this raises and the program stops.
                # The offset is never stored, so this event is retried on restart.
                is_new = store.save(alert)
                if is_new:
                    alerts += 1
                    true_label = event.get("label")
                    print(f"[{alert['severity'].upper()}] {alert['rule']} | {alert['user_id']} | "
                          f"{alert['details']}   (true label: {true_label})")

            # Only now is this message "done"
            consumer.store_offsets(message=msg)
            processed += 1
            if processed % 500 == 0:
                print(f"...processed {processed} events")
    except KeyboardInterrupt:
        print(f"\nStopping. Processed {processed}, skipped {skipped}, alerts saved {alerts}.")
    finally:
        consumer.close()
        store.close()


if __name__ == "__main__":
    main()
