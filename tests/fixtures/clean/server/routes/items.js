const router = require('express').Router();
const asyncHandler = require('../utils/asyncHandler');
const Item = require('../models/Item');
router.get('/', asyncHandler(async (req, res) => res.json(await Item.find({ companyId: req.user.companyId }))));
router.get('/:id', asyncHandler(async (req, res) => {
  const item = await Item.findOne({ _id: req.params.id, companyId: req.user.companyId });
  if (!item) return res.status(404).end();
  res.json(item);
}));
module.exports = router;
