import os
import time

from collections import deque

from core.utils import console

file_timestamps = deque()
error_timestamps = deque()
MAX_FILES_PER_MINUTE = int(os.getenv("VAULTIC_MAX_FILES_PER_MIN", "100"))
MAX_ERRORS = 10
ERROR_WINDOW = 60 # seconds

def throttle():
    time.sleep(0.25)

def can_process_file():
    now = time.time()
    while file_timestamps and now - file_timestamps[0] > 60:
        file_timestamps.popleft()
    return len(file_timestamps) < MAX_FILES_PER_MINUTE

def register_file_processed():
    file_timestamps.append(time.time())

def register_error():
    error_timestamps.append(time.time())
    now = time.time()
    while error_timestamps and now - error_timestamps[0] > ERROR_WINDOW:
        error_timestamps.popleft()
    if len(error_timestamps) >= MAX_ERRORS:
        console.print("[red]⚠ Too many errors, suspending 60s…[/red]")
        time.sleep(60)
        error_timestamps.clear()