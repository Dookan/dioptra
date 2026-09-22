const crypto = require("crypto");
// ok: js-weak-hash-algorithm
const digest = crypto.createHash("sha256").update(data).digest("hex");
// ok: js-math-random-for-secret
const resetToken = crypto.randomBytes(32).toString("hex");
// ok: js-math-random-for-secret
const jitter = Math.random() * 100;
