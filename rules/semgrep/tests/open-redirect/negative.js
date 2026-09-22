app.get("/go", (req, res) => {
  const target = ALLOWED[req.query.next] || "/";
  // ok: js-open-redirect
  res.redirect(target);
});
app.get("/home", (req, res) => {
  // ok: js-open-redirect
  res.redirect("/dashboard");
});
