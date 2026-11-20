const jwt = require('jsonwebtoken');
if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET missing');
exports.protect = (req, res, next) => { req.user = jwt.verify(String(req.headers.authorization || ''), process.env.JWT_SECRET); next(); };
exports.verifyApiKey = (req, res, next) => (req.get('x-api-key') === process.env.API_KEY ? next() : res.status(401).end());
exports.requireRole = (r) => (req, res, next) => (req.user.role === r ? next() : res.status(403).end());
