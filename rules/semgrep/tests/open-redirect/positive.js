app.get("/go", (req, res) => {
  // ruleid: js-open-redirect
  res.redirect(req.query.next);
});
app.get("/go2", (req, res) => {
  // ruleid: js-open-redirect
  res.redirect(302, req.body.returnTo);
});
