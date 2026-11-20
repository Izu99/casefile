const router = require('express').Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const asyncHandler = require('../utils/asyncHandler');
const User = require('../models/User');
router.post('/login', asyncHandler(async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) }).select('+password');
  if (!user || !(await bcrypt.compare(String(req.body.password), user.password))) return res.status(401).end();
  res.json({ token: jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '12h' }) });
}));
router.post('/register', asyncHandler(async (req, res) => {
  const { email, name } = req.body;
  const password = await bcrypt.hash(String(req.body.password), 12);
  const user = await User.create({ email: String(email), name: String(name), password, role: 'staff' });
  res.json({ id: user._id });
}));
function makeOtp() { return crypto.randomInt(100000, 1000000); }
module.exports = router;
module.exports.makeOtp = makeOtp;
