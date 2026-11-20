const jwt = require('jsonwebtoken');
exports.protect = (req, res, next) => { req.user = jwt.verify(req.headers.authorization, process.env.JWT_SECRET || 'devsecret'); next(); };
exports.requireRole = (r) => (req, res, next) => (req.user.role === r ? next() : res.status(403).end());
