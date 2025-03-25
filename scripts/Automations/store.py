import sqlite3
import argparse, os

# Database setup
DBS = os.environ['DBS']
DB_NAME = "/home/kali/Tools/scripts/db/strings.db"

def initialize_db():
    """Create the database and table if they don't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS strings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def add_string(value):
    """Add a string to the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO strings (value) VALUES (?)", (value,))
    conn.commit()
    conn.close()
    print(f"Added: {value}")

def list_strings():
    """List all strings in the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM strings")
    rows = cursor.fetchall()
    conn.close()
    if rows:
        print("Stored strings:")
        for row in rows:
            print(f"{row[0]}")
    else:
        print("No strings stored.")

def clear_strings():
    """Clear all strings from the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM strings")
    conn.commit()
    conn.close()
    print("All strings have been cleared.")

def main():
    """Main function to handle arguments."""
    parser = argparse.ArgumentParser(description="Manage strings with a SQLite database.")
    parser.add_argument("--add", metavar="STRING", help="Add a string to the database.")
    parser.add_argument("--list", action="store_true", help="List all stored strings.")
    parser.add_argument("--clear", action="store_true", help="Clear all stored strings.")
    args = parser.parse_args()

    initialize_db()

    if args.add:
        add_string(args.add)
    elif args.list:
        list_strings()
    elif args.clear:
        clear_strings()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
