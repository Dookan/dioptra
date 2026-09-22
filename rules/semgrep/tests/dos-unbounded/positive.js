const Ajv = require("ajv");
// ruleid: js-ajv-all-errors
const ajv = new Ajv({ allErrors: true });
function search(req) {
  // ruleid: js-regexp-from-input
  const re = new RegExp(req.query.q);
  // ruleid: js-regexp-from-input
  return new RegExp("^" + req.query.prefix, "i");
}
