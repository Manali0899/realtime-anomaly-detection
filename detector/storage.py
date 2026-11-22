import os

import psycopg

# Read the connection from an environment variable, with a local-dev default.
DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://detector:detector@localhost:5433/anomalies"
)

# %(name)s placeholders: psycopg fills them in safely. Never build SQL with f-strings.
INSERT_ALERT = """
    INSERT INTO alerts (alert_id, detected_at, event_timestamp, user_id,
                        rule, severity, details, event_id)
    VALUES (%(alert_id)s::uuid, %(detected_at)s::timestamptz, %(event_timestamp)s::timestamptz,
            %(user_id)s, %(rule)s, %(severity)s, %(details)s, %(event_id)s::uuid)
    ON CONFLICT (event_id, rule) DO NOTHING
"""


class AlertStore:
    def __init__(self, url=DATABASE_URL):
        self.conn = psycopg.connect(url, autocommit=True)

    def save(self, alert):
        """Returns True if the alert was new, False if it was a duplicate."""
        cursor = self.conn.execute(INSERT_ALERT, alert)
        return cursor.rowcount == 1

    def close(self):
        self.conn.close()
