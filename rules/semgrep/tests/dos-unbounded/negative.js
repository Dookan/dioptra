const Ajv = require("ajv");
// ok: js-ajv-all-errors
const ajv = new Ajv({ strict: true });
function search(req) {
  // ok: js-regexp-from-input
  const re = new RegExp("^[a-z]+$", "i");
  return re.test(req.query.q);
}
