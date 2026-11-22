import json

from confluent_kafka import Consumer

from detector.detector import Detector

TOPIC = "security-events"


def main():
    consumer = Consumer({
        "bootstrap.servers": "localhost:9092",
        "group.id": "anomaly-detector",
        "auto.offset.reset": "earliest",
    })
    consumer.subscribe([TOPIC])
    detector = Detector()
    processed = skipped = alerts = 0

    print(f"Listening on '{TOPIC}'. Ctrl+C to stop.")
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
                # Poison message: log where it is and keep going instead of crashing
                skipped += 1
                print(f"Skipping bad message (partition {msg.partition()}, offset {msg.offset()}): {err!r}")
                continue

            processed += 1             
            if processed % 500 == 0:
                print(f"...processed {processed} events")
            
            if alert:
                alerts += 1
                # Reading the label HERE is fine: this is evaluation output, not detection
                true_label = event.get("label")
                print(f"[{alert['severity'].upper()}] {alert['rule']} | {alert['user_id']} | "
                      f"{alert['details']}   (true label: {true_label})")
    except KeyboardInterrupt:
        print(f"\nStopping. Processed {processed}, skipped {skipped}, alerts {alerts}.")
    finally:
        consumer.close()


if __name__ == "__main__":
    main()