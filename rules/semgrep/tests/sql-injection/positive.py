def find(cursor, request):
    user_id = request.args["id"]
    # ruleid: python-sql-string-format
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    # ruleid: python-sql-string-format
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
    # ruleid: python-sql-string-format
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
