import json
from typing import Any, Optional

_IN_MEMORY_CACHE: dict[str, Any] = {}

def get_cache(key: str) -> Optional[Any]:
    """Retrieve value from Redis/in-memory cache."""
    return _IN_MEMORY_CACHE.get(key)

def set_cache(key: str, data: Any, ttl_seconds: int = 3600) -> None:
    """Set value in Redis/in-memory cache."""
    _IN_MEMORY_CACHE[key] = data

def delete_cache(key: str) -> None:
    """Delete key from cache."""
    _IN_MEMORY_CACHE.pop(key, None)
