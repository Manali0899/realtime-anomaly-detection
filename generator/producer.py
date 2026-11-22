import json
import random
import time

from confluent_kafka import Producer

from generator.events import (
    USERS,
    brute_force_burst,
    data_exfiltration,
    impossible_travel,
    normal_event,
)

TOPIC = "security-events"
EVENTS_PER_SECOND = 20
ATTACK_PROBABILITY = 0.01  # 1% of ticks start an attack (~one every 5 seconds)

ATTACKS = [brute_force_burst, impossible_travel, data_exfiltration]


def delivery_report(err, msg):
    """Kafka calls this once it confirms (or fails) each message."""
    if err is not None:
        print(f"Delivery failed for key {msg.key()}: {err}")


def send(producer, event):
    producer.produce(
        TOPIC,
        key=event["user_id"],  # same user -> same partition -> events stay in order
        value=json.dumps(event),
        callback=delivery_report,
    )


def main():
    producer = Producer({"bootstrap.servers": "localhost:9092"})
    sent = 0
    print(f"Producing ~{EVENTS_PER_SECOND} events/sec to '{TOPIC}'. Ctrl+C to stop.")
    try:
        while True:
            user = random.choice(USERS)
            if random.random() < ATTACK_PROBABILITY:
                attack = random.choice(ATTACKS)
                events = attack(user)
                print(f"Injected {events[0]['label']} for {user} ({len(events)} events)")
            else:
                events = [normal_event(user)]

            for event in events:
                send(producer, event)
                sent += 1

            producer.poll(0)  # lets the client run delivery callbacks
            time.sleep(1 / EVENTS_PER_SECOND)
    except KeyboardInterrupt:
        print(f"\nStopping. Sent {sent} events.")
    finally:
        producer.flush()  # send anything still buffered before exiting


if __name__ == "__main__":
    main()