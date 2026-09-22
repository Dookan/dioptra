const crypto = require("crypto");
// ruleid: js-weak-hash-algorithm
const digest = crypto.createHash("md5").update(password).digest("hex");
// ruleid: js-weak-hash-algorithm
const sha = crypto.createHash("sha1");
// ruleid: js-math-random-for-secret
const resetToken = Math.random().toString(36).slice(2);
// ruleid: js-math-random-for-secret
const otpCode = Math.floor(Math.random() * 1000000);
