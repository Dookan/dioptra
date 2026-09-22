async function update(req, res) {
  const user = await User.findById(req.params.id);
  // ruleid: js-mass-assignment-request-body
  Object.assign(user, req.body);
  // ruleid: js-mass-assignment-request-body
  await User.create(req.body);
  // ruleid: js-mass-assignment-request-body
  const doc = new Profile(req.body);
  // ruleid: js-mass-assignment-request-body
  const merged = { ...req.body };
  return res.json({ doc, merged });
}
