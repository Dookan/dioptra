const serialize = require("node-serialize");
const yaml = require("js-yaml");
function load(req) {
  // ruleid: js-unsafe-deserialization
  const obj = serialize.unserialize(req.body.data);
  // ruleid: js-unsafe-deserialization
  const cfg = yaml.load(req.body.yaml, { schema: yaml.DEFAULT_FULL_SCHEMA });
  return { obj, cfg };
}
