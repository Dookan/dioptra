function find(db, req) {
  // ruleid: js-sql-string-concat
  db.query("SELECT * FROM users WHERE id = " + req.params.id);
  // ruleid: js-sql-string-concat
  return db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
}
