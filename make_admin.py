
import sys
from database import get_db

# Make sure a username is provided.
if len(sys.argv) != 2:
    print("Usage: python make_admin.py <username>")
    sys.exit(1)

username = sys.argv[1]

conn = get_db()

# Check if the account exists before changing its role.
user = conn.execute(
    "SELECT id FROM users WHERE username = ?",
    (username,)
).fetchone()

if user is None:
    print("User not found.")
else:
    conn.execute(
        # Assign the admin role to the existing account.
        "UPDATE users SET role = 'admin' WHERE username = ?",
        (username,)
    )
    conn.commit()
    print(f"{username} is now an admin.")

conn.close()
