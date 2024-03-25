import sqlite3

def list_tables(database_file):
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(database_file)
        cursor = conn.cursor()

        try:
            # Execute the query to list tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            # Fetch all the table names
            tables = cursor.fetchall()
            # Print the table names
            print("Tables in the database:")
            for table in tables:
                print(table[0])
        except sqlite3.DatabaseError as e:
            print("SQLite database error:", e)
        finally:
            # Close the cursor and the database connection
            cursor.close()
            conn.close()
    except sqlite3.Error as e:
        print("SQLite error:", e)

def query_database(database_file, query):
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(database_file)
        cursor = conn.cursor()

        try:
            # Execute the query
            cursor.execute(query)
            # Fetch the first 10 rows
            #results = cursor.fetchall()
            results = cursor.fetchmany(10)
            # Print the results
            for row in results:
                print(row)
            
        except sqlite3.DatabaseError as e:
            print("SQLite database error:", e)
        finally:
            # Close the cursor and the database connection
            cursor.close()
            conn.close()
    except sqlite3.Error as e:
        print("SQLite error:", e)


def print_table_headers(database_file, table_name):
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(database_file)
        cursor = conn.cursor()

        try:
            # Execute the query to fetch column names
            cursor.execute(f"PRAGMA table_info({table_name});")
            # Fetch all the column names
            headers = cursor.fetchall()
            # Print the column names
            print("Table headers (column names) for", table_name, ":")
            for header in headers:
                print(header[1])  # The column name is in the second position of the tuple
        except sqlite3.DatabaseError as e:
            print("SQLite database error:", e)
        finally:
            # Close the cursor and the database connection
            cursor.close()
            conn.close()
    except sqlite3.Error as e:
        print("SQLite error:", e)





# Example usage:
        
database_file = "/home/ihakami/Downloads/RDS_2021.12.2_curated.db"  # Update with your database file path
list_tables(database_file)               # List tables

query = "SELECT * FROM METADATA WHERE file_name LIKE '%.exe';"     # Update with your SQL query
query_database(database_file, query)    # Query the database
#print_table_headers(database_file, 'METADATA')



