import sqlite3

conn = sqlite3.connect('garbage.sqlite', check_same_thread=False)


def fetchone_by_name(name):
    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT category FROM garbage WHERE name=?", (name,))
        row = cursor.fetchone()
        if row:
            return row[0]
        else:
            return None
