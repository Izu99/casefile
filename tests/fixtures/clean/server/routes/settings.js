const router = require('express').Router();
router.get('/', (req, res) => res.json({}));
module.exports = router;
const { verifyApiKey } = require('../middleware/auth');
router.post('/sync', verifyApiKey, (req, res) => res.json({}));
