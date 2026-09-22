app.use((err, req, res, next) => {
  // ruleid: js-error-stack-in-response
  res.status(500).send(err.stack);
});
app.use((err, req, res, next) => {
  // ruleid: js-error-stack-in-response
  res.status(500).json({ message: err.message, stack: err.stack });
});
