const bad = (v) => v && typeof v === 'object' && Object.keys(v).some((k) => k.startsWith('$') || bad(v[k]));
module.exports = (req, res, next) => (bad(req.body) || bad(req.query) ? res.status(400).end() : next());
