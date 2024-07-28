class Transaction:
    def __init__(self, database):
        self.database = database
        self.changes = []

    def insert(self, table_name, **kwargs):
        self.changes.append(('insert', table_name, kwargs))

    def commit(self):
        self.database.commit(self.changes)
        self.changes = []

class TransactionManager:
    def __init__(self, database):
        self.database = database

    def start_transaction(self):
        return Transaction(self.database)
