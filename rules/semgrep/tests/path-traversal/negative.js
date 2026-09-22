const fs = require("fs");
const path = require("path");
app.get("/download", (req, res) => {
  const safe = path.basename(req.query.file);
  const full = path.resolve(UPLOADS, safe);
  if (!full.startsWith(UPLOADS)) return res.status(400).end();
  // ok: js-path-traversal
  const data = fs.readFileSync(full);
  // ok: js-path-traversal
  res.sendFile("/srv/static/index.html");
  res.send(data);
});
