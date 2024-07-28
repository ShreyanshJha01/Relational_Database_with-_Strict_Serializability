import threading

class LockManager:
    def __init__(self):
        self.locks = {}
        self.lock = threading.Lock()

    def acquire_lock(self, table_name):
        with self.lock:
            if table_name not in self.locks:
                self.locks[table_name] = threading.Lock()
            self.locks[table_name].acquire()

    def release_lock(self, table_name):
        with self.lock:
            if table_name in self.locks:
                self.locks[table_name].release()


