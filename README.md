Relational Database with Transaction Support

Project Overview

This project implements a basic relational database with support for transactions and strict serializability. The database persists data to disk, ensuring data integrity even in the event of interruptions or crashes. The project includes features for creating tables, inserting data, managing transactions, and committing changes.

Features
Table Management: Create and manage tables with specified columns.
Data Insertion: Insert data into tables within transactions.
Transactions: Support for transactions with commit functionality.
Data Persistence: Persist data to a JSON file to ensure data is saved between sessions.
Data Integrity: Ensure data is not corrupted in case of crashes or interruptions.
Interactive CLI: User-friendly command-line interface to interact with the database.
