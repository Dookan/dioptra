app.get("/hello", (req, res) => {
  // ok: js-express-reflected-xss
  res.send("<h1>Hola</h1>");
  // ok: js-express-reflected-xss
  res.json({ name: req.query.name });
});
function render(el, data) {
  // ok: js-dom-innerhtml-assignment
  el.textContent = data.description;
  // ok: js-dom-innerhtml-assignment
  el.innerHTML = "<b>fixed</b>";
}
