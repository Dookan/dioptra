const fs = require("fs");
const path = require("path");
app.get("/download", (req, res) => {
  // ruleid: js-path-traversal
  const data = fs.readFileSync(path.join(UPLOADS, req.query.file));
  // ruleid: js-path-traversal
  res.sendFile(UPLOADS + req.params.name);
  res.send(data);
});
