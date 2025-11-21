import shelve
import threading
import sqlite3
import pickle
import os


class ThreadSafeSQLiteDict:
    """A thread-safe SQLite-backed dictionary for use with shelve."""
    
    def __init__(self, filename):
        self.filename = filename
        self._lock = threading.RLock()
        # Create connection with check_same_thread=False
        self._conn = sqlite3.connect(filename, check_same_thread=False)
        self._conn.execute(
            'CREATE TABLE IF NOT EXISTS shelf (key TEXT PRIMARY KEY, value BLOB)'
        )
        self._conn.commit()
    
    def __getitem__(self, key):
        with self._lock:
            cursor = self._conn.execute('SELECT value FROM shelf WHERE key = ?', (key,))
            row = cursor.fetchone()
            if row is None:
                raise KeyError(key)
            return pickle.loads(row[0])
    
    def __setitem__(self, key, value):
        with self._lock:
            self._conn.execute(
                'INSERT OR REPLACE INTO shelf (key, value) VALUES (?, ?)',
                (key, pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL))
            )
            self._conn.commit()
    
    def __delitem__(self, key):
        with self._lock:
            cursor = self._conn.execute('DELETE FROM shelf WHERE key = ?', (key,))
            if cursor.rowcount == 0:
                raise KeyError(key)
            self._conn.commit()
    
    def __contains__(self, key):
        with self._lock:
            cursor = self._conn.execute('SELECT 1 FROM shelf WHERE key = ?', (key,))
            return cursor.fetchone() is not None
    
    def keys(self):
        with self._lock:
            cursor = self._conn.execute('SELECT key FROM shelf')
            return [row[0] for row in cursor.fetchall()]
    
    def clear(self):
        with self._lock:
            self._conn.execute('DELETE FROM shelf')
            self._conn.commit()
    
    def close(self):
        with self._lock:
            self._conn.close()


class SessionHandler:
    def __init__(self, mode='shelve', namespace='sessions', **kwargs):
        self.mode = mode
        self._lock = threading.RLock()
        if mode == 'shelve':
            filename = kwargs.get('filename', 'session_data/sessions.db')
            # Ensure directory exists
            os.makedirs(os.path.dirname(filename) if os.path.dirname(filename) else '.', exist_ok=True)
            
            # Use our custom thread-safe SQLite dict
            self.shelve_store = ThreadSafeSQLiteDict(filename)
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

