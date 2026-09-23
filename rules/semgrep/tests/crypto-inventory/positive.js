const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const tls = require("tls");

function digests(data, key) {
  // ruleid: crypto-inventory-js-hash
  const strong = crypto.createHash("sha256").update(data).digest("hex");
  // ruleid: crypto-inventory-js-weak-hash
  const weak = crypto.createHash("md5").update(data).digest("hex");
  // ruleid: crypto-inventory-js-hmac
  const mac = crypto.createHmac("sha512", key).update(data).digest("hex");
  // ruleid: crypto-inventory-js-weak-hmac
  const weakMac = crypto.createHmac("sha1", key).update(data).digest("hex");
  return [strong, weak, mac, weakMac];
}

function ciphers(key, iv, secret) {
  // ruleid: crypto-inventory-js-cipher
  const gcm = crypto.createCipheriv("aes-256-gcm", key, iv);
  // ruleid: crypto-inventory-js-weak-cipher
  const legacy = crypto.createCipheriv("des-ede3-cbc", key, iv);
  // ruleid: crypto-inventory-js-kdf
  const derived = crypto.scryptSync(secret, "salt", 32);
  // ruleid: crypto-inventory-js-keypair
  const pair = crypto.generateKeyPairSync("ed25519");
  return [gcm, legacy, derived, pair];
}

function tokens(payload, secret) {
  // ruleid: crypto-inventory-js-jwt-signature
  return jwt.sign(payload, secret, { algorithm: "HS256", expiresIn: "15m" });
}

function server(options) {
  // ruleid: crypto-inventory-js-weak-protocol
  return tls.createServer({ ...options, minVersion: "TLSv1" });
}

module.exports = { digests, ciphers, tokens, server };
