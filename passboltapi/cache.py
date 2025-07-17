"""
Caching utilities for the Passbolt API client.
"""
import time
from typing import Any, Dict, Optional, TypeVar, Callable
from functools import wraps

T = TypeVar('T')

class CacheEntry:
    """A single cache entry with value and expiration time."""
    
    __slots__ = ('value', 'expires_at')
    
    def __init__(self, value: Any, ttl: float):
        self.value = value
        self.expires_at = time.time() + ttl if ttl > 0 else float('inf')
    
    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        return time.time() > self.expires_at


class Cache:
    """A simple in-memory cache with TTL support."""
    
    def __init__(self, default_ttl: float = 300):
        """
        Initialize the cache.
        
        Args:
            default_ttl: Default time-to-live in seconds for cache entries.
        """
        self._cache: Dict[str, CacheEntry] = {}
        self.default_ttl = default_ttl
    
    def get(self, key: str) -> Any:
        """
        Get a value from the cache.
        
        Args:
            key: Cache key
            
        Returns:
            The cached value or None if not found or expired
        """
        entry = self._cache.get(key)
        if entry is None or entry.is_expired():
            if entry is not None:
                del self._cache[key]
            return None
        return entry.value
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """
        Set a value in the cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if None)
        """
        ttl = ttl if ttl is not None else self.default_ttl
        self._cache[key] = CacheEntry(value, ttl)
    
    def delete(self, key: str) -> None:
        """
        Remove a key from the cache.
        
        Args:
            key: Cache key to remove
        """
        self._cache.pop(key, None)
    
    def clear(self) -> None:
        """Clear all entries from the cache."""
        self._cache.clear()
    
    def cached(self, key_func: Optional[Callable[..., str]] = None, ttl: Optional[float] = None):
        """
        Decorator to cache function results.
        
        Args:
            key_func: Function to generate cache key from function arguments
            ttl: Time-to-live in seconds (uses default if None)
            
        Returns:
            Decorator function
        """
        def decorator(func):
            @wraps(func)
            def wrapper(self, *args, **kwargs):
                if not hasattr(self, '_cache'):
                    return func(self, *args, **kwargs)
                    
                if key_func is not None:
                    cache_key = key_func(self, *args, **kwargs)
                else:
                    # Default key is function name + str(args) + str(kwargs)
                    cache_key = f"{func.__name__}:{args}:{sorted(kwargs.items())}"
                
                # Try to get from cache
                cached_result = self._cache.get(cache_key)
                if cached_result is not None:
                    return cached_result
                
                # Call the function and cache the result
                result = func(self, *args, **kwargs)
                if result is not None:
                    self._cache.set(cache_key, result, ttl=ttl)
                
                return result
            return wrapper
        return decorator


# Global cache instance
default_cache = Cache()
