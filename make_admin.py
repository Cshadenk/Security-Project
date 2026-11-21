
import sys
from database import get_db

if len(sys.argv) != 2:
    print("Usage: python make_admin.py <username>")
    sys.exit(1)

username = sys.argv[1]

conn = get_db()

user = conn.execute(
    "SELECT id FROM users WHERE username = ?",
    (username,)
).fetchone()

if user is None:
    print("User not found.")
else:
    conn.execute(
        "UPDATE users SET role = 'admin' WHERE username = ?",
        (username,)
    )
    conn.commit()
    print(f"{username} is now an admin.")

conn.close()
