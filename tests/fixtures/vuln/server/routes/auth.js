const router = require('express').Router();
const c = require('../controllers/auth');
router.post('/login', c.login);
router.post('/register', c.register);
module.exports = router;
