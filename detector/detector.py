import math
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

# Tuning knobs. In a real system these come from config, not code.
BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW = timedelta(seconds=60)
MAX_TRAVEL_SPEED_KMH = 1000
ZSCORE_THRESHOLD = 4.0
MIN_BASELINE_SAMPLES = 20


def haversine_km(lat1, lon1, lat2, lon2):
    """Distance between two points on Earth, in km."""
    radius_km = 6371
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    return 2 * radius_km * math.asin(math.sqrt(a))


class RunningStats:
    """Mean and standard deviation updated one value at a time (Welford's algorithm)."""

    def __init__(self):
        self.count = 0
        self.mean = 0.0
        self._m2 = 0.0

    def update(self, value):
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self._m2 += delta * (value - self.mean)

    @property
    def std(self):
        if self.count < 2:
            return 0.0
        return math.sqrt(self._m2 / (self.count - 1))

    def zscore(self, value):
        """How many standard deviations above this user's average a value is."""
        if self.std == 0:
            return 0.0
        return (value - self.mean) / self.std


class Detector:
    def __init__(self):
        # Per-user state. defaultdict creates an empty entry the first time we see a user.
        self.failed_logins = defaultdict(deque)
        self.last_login = {}
        self.bytes_stats = defaultdict(RunningStats)

    def process(self, event):
        """Takes one event, returns an alert dict or None. Never reads event['label']."""
        timestamp = datetime.fromisoformat(event["timestamp"])
        if event["event_type"] == "login":
            if event["status"] == "failure":
                alert = self._check_brute_force(event, timestamp)
            else:
                alert = self._check_impossible_travel(event, timestamp)
        elif event["event_type"] == "web_request":
            alert = self._check_large_upload(event)
        else:
            alert = None
        return alert

    def _check_brute_force(self, event, timestamp):
        failures = self.failed_logins[event["user_id"]]
        failures.append(timestamp)
        # Slide the window: drop failures older than 60 seconds
        while failures and timestamp - failures[0] > BRUTE_FORCE_WINDOW:
            failures.popleft()

        if len(failures) >= BRUTE_FORCE_THRESHOLD:
            count = len(failures)
            failures.clear()  # reset so one attack doesn't fire 6 alerts
            return _make_alert(event, "brute_force", "high",
                               f"{count} failed logins within {BRUTE_FORCE_WINDOW.seconds}s from {event['city']}")
        return None

    def _check_impossible_travel(self, event, timestamp):
        user = event["user_id"]
        previous = self.last_login.get(user)

        if previous is not None:
            distance = haversine_km(previous["lat"], previous["lon"], event["lat"], event["lon"])
            # Avoid dividing by zero when two logins share a timestamp
            hours = max((timestamp - previous["timestamp"]).total_seconds() / 3600, 1 / 3600)
            speed = distance / hours
            if distance > 500 and speed > MAX_TRAVEL_SPEED_KMH:
                # Return BEFORE updating last_login: a suspicious login must not
                # become the user's new "known location" (no baseline poisoning)
                return _make_alert(event, "impossible_travel", "high",
                                   f"{previous['city']} -> {event['city']}: "
                                   f"{distance:,.0f} km at {speed:,.0f} km/h")

        self.last_login[user] = {"timestamp": timestamp, "lat": event["lat"],
                                 "lon": event["lon"], "city": event["city"]}
        return None

    def _check_large_upload(self, event):
        stats = self.bytes_stats[event["user_id"]]
        bytes_out = event["bytes_out"]

        if stats.count >= MIN_BASELINE_SAMPLES:  # cold start: no judging until we know the user
            z = stats.zscore(bytes_out)
            if z > ZSCORE_THRESHOLD:
                # Don't update the baseline with the attack
                return _make_alert(event, "large_upload", "critical",
                                   f"{bytes_out / 1_000_000:.1f} MB to {event['dest_domain']} "
                                   f"(z-score {z:,.0f}, user avg {stats.mean / 1000:.0f} KB)")

        stats.update(bytes_out)
        return None


def _make_alert(event, rule, severity, details):
    return {
        "alert_id": str(uuid.uuid4()),
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "user_id": event["user_id"],
        "rule": rule,
        "severity": severity,
        "details": details,
        "event_id": event["event_id"],
        "event_timestamp": event["timestamp"],
    }