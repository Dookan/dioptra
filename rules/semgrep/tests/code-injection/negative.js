function run(cb) {
  // ok: js-eval-injection
  setTimeout(cb, 10);
  // ok: js-eval-injection
  setTimeout(() => cb(1), 10);
  // ok: js-eval-injection
  eval("1 + 1");
}
