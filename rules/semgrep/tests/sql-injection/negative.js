function find(db, req) {
  // ok: js-sql-string-concat
  db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  // ok: js-sql-string-concat
  return db.query("SELECT * FROM users");
}
