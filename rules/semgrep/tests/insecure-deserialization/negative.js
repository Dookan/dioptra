const yaml = require("js-yaml");
function load(req) {
  // ok: js-unsafe-deserialization
  const obj = JSON.parse(req.body.data);
  // ok: js-unsafe-deserialization
  const cfg = yaml.load(req.body.yaml);
  return { obj, cfg };
}
