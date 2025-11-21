import shelve


class SessionHandler:
    def __init__(self, mode='shelve', namespace='sessions', **kwargs):
        self.mode = mode
        if mode == 'shelve':
            filename = kwargs.get('filename', 'session_data/sessions.db')
            self.shelve_store = shelve.open(filename)
        else:
            raise Exception(f"Unknown mode: {mode}")

    def reset_keys(self):
        if self.mode == 'shelve':
            self.shelve_store.clear()

    def set(self, key_name, value: any):
        if self.mode == 'shelve':
            self.shelve_store[key_name] = value

    def get(self, key_name, default=None):
        if self.mode == 'shelve':
            if key_name in self.shelve_store:
                return self.shelve_store[key_name]
        return default

    def has_session_key(self, key_name):
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
        if self.mode == 'shelve':
            del self.shelve_store[key_name]

    def keys(self):
        if self.mode == 'shelve':
            return self.shelve_store.keys()

