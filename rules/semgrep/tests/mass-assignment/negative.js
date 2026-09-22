async function update(req, res) {
  const user = await User.findById(req.params.id);
  // ok: js-mass-assignment-request-body
  Object.assign(user, { name: req.body.name, email: req.body.email });
  // ok: js-mass-assignment-request-body
  await User.create({ name: req.body.name });
  return res.json(user);
}
