import json
import os

class Table:
    def __init__(self, name, columns):
        self.name = name
        self.columns = columns
        self.rows = []

    def insert(self, **kwargs):
        row = {col: kwargs.get(col, None) for col in self.columns}
        self.rows.append(row)

    def serialize(self):
        return {'columns': self.columns, 'rows': self.rows}

    def deserialize(self, data):
        self.columns = data['columns']
        self.rows = data['rows']

    def __repr__(self):
        return f"Table(name={self.name}, columns={self.columns}, rows={self.rows})"

    def print_table(self):
        print(f"Table: {self.name}")
        print(" | ".join(self.columns))
        print("-" * (len(self.columns) * 15))
        for row in self.rows:
            print(" | ".join(str(row[col]) for col in self.columns))
        print()

class Database:
    def __init__(self, db_file):
        self.tables = {}
        self.db_file = db_file
        self.load_data()

    def create_table(self, name, columns):
        if name not in self.tables:
            self.tables[name] = Table(name, columns)

    def insert(self, table_name, **kwargs):
        if table_name in self.tables:
            self.tables[table_name].insert(**kwargs)
        else:
            raise ValueError(f"Table {table_name} does not exist")

    def commit(self, changes):
        for change in changes:
            action, table_name, data = change
            if action == 'insert':
                self.insert(table_name, **data)
        self.persist_data()

    def persist_data(self):
        with open(self.db_file, 'w') as f:
            json.dump({table_name: table.serialize() for table_name, table in self.tables.items()}, f, indent=4)

    def load_data(self):
        if os.path.exists(self.db_file):
            with open(self.db_file, 'r') as f:
                data = json.load(f)
                for table_name, table_data in data.items():
                    columns = table_data['columns']
                    table = Table(table_name, columns)
                    table.deserialize(table_data)
                    self.tables[table_name] = table

    def __repr__(self):
        return f"Database(tables={self.tables})"

    def print_database(self):
        for table in self.tables.values():
            table.print_table()
