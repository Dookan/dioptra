def find(cursor, request):
    user_id = request.args["id"]
    # ok: python-sql-string-format
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    # ok: python-sql-string-format
    cursor.execute("SELECT COUNT(*) FROM users")
