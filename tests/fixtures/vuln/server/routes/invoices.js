const router = require('express').Router();
const c = require('../controllers/invoices');
router.route('/').get(c.list).post(c.create);
router.get('/:id', c.getOne);
module.exports = router;
