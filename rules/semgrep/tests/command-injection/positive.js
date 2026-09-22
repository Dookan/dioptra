const { exec, execSync } = require("child_process");
const cp = require("child_process");
function run(req) {
  // ruleid: js-child-process-shell-injection
  exec("ls " + req.query.dir);
  // ruleid: js-child-process-shell-injection
  execSync(`convert ${req.body.file} out.png`);
  // ruleid: js-child-process-shell-injection
  cp.exec(req.body.cmd, () => {});
}
