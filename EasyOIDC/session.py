import shelve
import threading
import dbm.sqlite3
import os


class SessionHandler:
    def __init__(self, mode='shelve', namespace='sessions', **kwargs):
        self.mode = mode
        self._lock = threading.RLock()
        if mode == 'shelve':
            filename = kwargs.get('filename', 'session_data/sessions.db')
            # Ensure directory exists
            os.makedirs(os.path.dirname(filename) if os.path.dirname(filename) else '.', exist_ok=True)
            
            # Open dbm.sqlite3 with check_same_thread=False for thread safety
            # We use the lock to ensure thread-safe access
            self._db = dbm.sqlite3.open(filename, 'c', check_same_thread=False)
            self.shelve_store = shelve.Shelf(self._db)
        else:
            raise Exception(f"Unknown mode: {mode}")

    def reset_keys(self):
        with self._lock:
            if self.mode == 'shelve':
                self.shelve_store.clear()

    def set(self, key_name, value: any):
        with self._lock:
            if self.mode == 'shelve':
                self.shelve_store[key_name] = value

    def get(self, key_name, default=None):
        with self._lock:
            if self.mode == 'shelve':
                if key_name in self.shelve_store:
                    return self.shelve_store[key_name]
            return default

    def has_session_key(self, key_name):
        with self._lock:
            if self.mode == 'shelve':
                return key_name in self.shelve_store
            return False

    def __setitem__(self, key_name: str, value: any):
        self.set(key_name, value)

    def __getitem__(self, key_name: str):
        return self.get(key_name)

    def __contains__(self, item):
        return self.has_session_key(item)

    def __delitem__(self, key_name: str):
        with self._lock:
            if self.mode == 'shelve':
                del self.shelve_store[key_name]

    def keys(self):
        with self._lock:
            if self.mode == 'shelve':
                return list(self.shelve_store.keys())

