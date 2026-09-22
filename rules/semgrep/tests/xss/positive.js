app.get("/hello", (req, res) => {
  // ruleid: js-express-reflected-xss
  res.send("<h1>Hola " + req.query.name + "</h1>");
});
app.get("/bye", (req, res) => {
  // ruleid: js-express-reflected-xss
  res.send(`<p>${req.body.comment}</p>`);
});
function render(el, data) {
  // ruleid: js-dom-innerhtml-assignment
  el.innerHTML = data.description;
  // ruleid: js-dom-innerhtml-assignment
  el.insertAdjacentHTML("beforeend", data.html);
}
