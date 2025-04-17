"""
DoS Utilities - Functions for rate limiting and preventing resource exhaustion.
"""
import time
import threading
from typing import Dict

# Global state variables
_last_processed_time = 0.0
_processed_count = 0
_error_count = 0
_lock = threading.Lock()

# Configuration parameters
DEFAULT_MIN_INTERVAL = 0.25  # seconds between processing files
DEFAULT_MAX_RATE = 10  # files per second
DEFAULT_MAX_ERRORS = 5  # maximum consecutive errors before cooldown
ERROR_COOLDOWN = 2.0  # seconds to wait after hitting max errors

def throttle(interval: float = DEFAULT_MIN_INTERVAL) -> None:
    """
    Sleep for a minimum interval to prevent resource exhaustion.
    
    Args:
        interval (float): Minimum time between operations in seconds
    """
    time.sleep(interval)

def can_process_file() -> bool:
    """
    Check if a file can be processed based on rate limits.
    
    Returns:
        bool: True if processing is allowed, False otherwise
    """
    global _last_processed_time, _processed_count, _error_count
    
    with _lock:
        now = time.time()

        # Check error cooldown
        if _error_count >= DEFAULT_MAX_ERRORS:
            if now - _last_processed_time < ERROR_COOLDOWN:
                return False
            # Reset error count after cooldown
            _error_count = 0

        # Check time-based rate limit
        elapsed = now - _last_processed_time
        if elapsed < DEFAULT_MIN_INTERVAL:
            return False

        # Check count-based rate limit
        if _processed_count >= DEFAULT_MAX_RATE:
            if elapsed < 1.0:  # Reset count after 1 second
                return False
            _processed_count = 0

        return True

def register_file_processed() -> None:
    """
    Register that a file has been processed to enforce rate limiting.
    """
    global _last_processed_time, _processed_count

    with _lock:
        _last_processed_time = time.time()
        _processed_count += 1

def register_error() -> bool:
    """
    Register an error occurrence to enable cooldown if too many errors happen.
    
    Returns:
        bool: True if max errors exceeded, False otherwise
    """
    global _error_count

    with _lock:
        _error_count += 1
        return _error_count >= DEFAULT_MAX_ERRORS

def reset_counters() -> None:
    """
    Reset all rate limiting counters (for testing purposes).
    """
    global _last_processed_time, _processed_count, _error_count

    with _lock:
        _last_processed_time = 0.0
        _processed_count = 0
        _error_count = 0