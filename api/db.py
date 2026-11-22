import os

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://detector:detector@localhost:5433/anomalies"
)

# Keep 1-5 connections open and lend them to requests.
# dict_row: rows come back as {"user_id": "user_017", ...} instead of tuples.
pool = ConnectionPool(
    DATABASE_URL,
    min_size=1,
    max_size=5,
    kwargs={"row_factory": dict_row},
    open=False,
)
