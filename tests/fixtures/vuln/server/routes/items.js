const router = require('express').Router();
const Item = require('../models/Item');
router.get('/', async (req, res) => {
  const items = await Item.find({ name: req.query.name });
  res.json(items);
});
router.delete('/:id', async (req, res) => {
  await Item.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});
module.exports = router;
