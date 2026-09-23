const crypto = require("crypto");

function nothingCryptographic(data) {
  // ok: crypto-inventory-js-hash
  const bytes = Buffer.from(data, "utf8");
  // ok: crypto-inventory-js-cipher
  const encoded = bytes.toString("base64");
  // ok: crypto-inventory-js-weak-protocol
  const options = { keepAlive: true, minDelay: "TLSv9" };
  return [encoded, options, crypto.constants];
}

module.exports = { nothingCryptographic };
