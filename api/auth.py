import os
import secrets

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

# Local default only. In production this comes from a secrets manager.
API_KEY = os.getenv("API_KEY", "dev-secret-key")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: str | None = Security(api_key_header)):
    # compare_digest takes the same time no matter where the keys differ,
    # so attackers can't guess the key by measuring response times.
    if api_key is None or not secrets.compare_digest(api_key, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
