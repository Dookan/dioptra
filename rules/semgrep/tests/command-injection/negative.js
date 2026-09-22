const { execFile, exec } = require("child_process");
function run(req) {
  // ok: js-child-process-shell-injection
  execFile("ls", [req.query.dir]);
  // ok: js-child-process-shell-injection
  exec("ls -la");
}
