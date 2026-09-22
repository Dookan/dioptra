function run(req) {
  // ruleid: js-eval-injection
  eval(req.body.expr);
  // ruleid: js-eval-injection
  const fn = new Function("a", req.query.body);
  // ruleid: js-eval-injection
  setTimeout("doThing(" + req.query.x + ")", 10);
  return fn;
}
