import random
import uuid
from datetime import datetime, timezone

# 50 fake users: user_001 ... user_050
USERS = [f"user_{i:03d}" for i in range(1, 51)]

# lat/lon are included so we can calculate travel distance later (impossible travel)
LOCATIONS = [
    {"city": "New York", "country": "US", "lat": 40.71, "lon": -74.01},
    {"city": "San Francisco", "country": "US", "lat": 37.77, "lon": -122.42},
    {"city": "London", "country": "GB", "lat": 51.51, "lon": -0.13},
    {"city": "Mumbai", "country": "IN", "lat": 19.08, "lon": 72.88},
    {"city": "Singapore", "country": "SG", "lat": 1.35, "lon": 103.82},
]

NORMAL_DOMAINS = ["github.com", "slack.com", "google.com", "office.com", "zoom.us"]
# ".example" is a reserved domain, so these can never be real websites
SUSPICIOUS_DOMAINS = ["exfil-drop.example", "temp-share.example"]

# A seeded random generator: every user gets the SAME home city on every run.
# Reproducible data makes debugging much easier.
_setup_rng = random.Random(42)
HOME = {user: _setup_rng.choice(LOCATIONS) for user in USERS}


def _fake_ip(location):
    city_index = LOCATIONS.index(location)
    return f"10.{city_index}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _base_event(user_id, event_type, location, label):
    """Fields every event has, whatever its type."""
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "event_type": event_type,
        "src_ip": _fake_ip(location),
        "city": location["city"],
        "country": location["country"],
        "lat": location["lat"],
        "lon": location["lon"],
        "label": label,  # ground truth: the detector must NEVER read this
    }


def normal_event(user_id):
    """Regular activity from the user's home city."""
    location = HOME[user_id]
    if random.random() < 0.3:  # 30% logins, 70% web requests
        event = _base_event(user_id, "login", location, "normal")
        # Real users mistype passwords sometimes, so a few failures are normal
        event["status"] = "success" if random.random() < 0.97 else "failure"
    else:
        event = _base_event(user_id, "web_request", location, "normal")
        event["dest_domain"] = random.choice(NORMAL_DOMAINS)
        event["bytes_out"] = random.randint(500, 50_000)
    return event


def brute_force_burst(user_id, attempts=15):
    """Many failed logins from a city that isn't the user's home."""
    attacker_location = random.choice([loc for loc in LOCATIONS if loc != HOME[user_id]])
    events = []
    for _ in range(attempts):
        event = _base_event(user_id, "login", attacker_location, "brute_force")
        event["status"] = "failure"
        events.append(event)
    return events


def impossible_travel(user_id):
    """Two successful logins, from two countries, seconds apart."""
    home = HOME[user_id]
    far_away = random.choice([loc for loc in LOCATIONS if loc["country"] != home["country"]])
    first = _base_event(user_id, "login", home, "impossible_travel")
    second = _base_event(user_id, "login", far_away, "impossible_travel")
    first["status"] = second["status"] = "success"
    return [first, second]


def data_exfiltration(user_id):
    """One huge upload to a suspicious domain."""
    event = _base_event(user_id, "web_request", HOME[user_id], "data_exfiltration")
    event["dest_domain"] = random.choice(SUSPICIOUS_DOMAINS)
    event["bytes_out"] = random.randint(50_000_000, 200_000_000)  # 50–200 MB
    return [event]