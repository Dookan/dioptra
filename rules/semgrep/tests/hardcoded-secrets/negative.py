import os

# ok: hardcoded-secret-assignment
DB_PASSWORD = os.environ["DB_PASSWORD"]
# ok: hardcoded-secret-assignment
password = "${DB_PASSWORD}"
