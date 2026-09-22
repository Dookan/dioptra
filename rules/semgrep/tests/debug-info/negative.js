app.use((err, req, res, next) => {
  logger.error(err.stack);
  // ok: js-error-stack-in-response
  res.status(500).json({ code: "internal_error" });
});
