import database as db_module
import transaction as t
import thread

def main():
    database = db_module.Database('test_db.json')
    lock_manager = thread.LockManager()

    transaction_manager = t.TransactionManager(database)
    current_transaction = None

    while True:
        print("Options: create_table, start_transaction, insert, commit, print, exit")
        choice = input("Enter your choice: ")

        if choice == "create_table":
            table_name = input("Enter table name: ")
            columns = input("Enter columns (comma-separated): ").split(',')
            database.create_table(table_name, [col.strip() for col in columns])
        
        elif choice == "start_transaction":
            current_transaction = transaction_manager.start_transaction()
            print("Transaction started.")
        
        elif choice == "insert":
            if current_transaction is None:
                print("No active transaction. Please start a transaction first.")
                continue
            table_name = input("Enter table name: ")
            if table_name not in database.tables:
                print(f"Table {table_name} does not exist.")
                continue
            row_data = {}
            for column in database.tables[table_name].columns:
                row_data[column] = input(f"Enter value for {column}: ")
            current_transaction.insert(table_name, **row_data)
        
        elif choice == "commit":
            if current_transaction is None:
                print("No active transaction to commit.")
            else:
                current_transaction.commit()
                current_transaction = None
                print("Transaction committed.")
        
        elif choice == "print":
            database.print_database()
        
        elif choice == "exit":
            database.persist_data()
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
