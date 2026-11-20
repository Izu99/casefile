const Invoice = require('../models/Invoice');
const multer = require('multer');
exports.upload = multer({ dest: 'uploads/' });
exports.list = async (req, res) => {
  try { res.json(await Invoice.find({ companyId: req.user.companyId, $where: 'this.total > 0' })); }
  catch (err) { res.status(500).json({ error: err.message, stack: err.stack }); }
};
exports.getOne = async (req, res) => {
  try { res.json(await Invoice.findById(req.params.id)); } catch (e) { res.status(500).end(); }
};
exports.create = async (req, res) => {
  try {
    const no = (await Invoice.countDocuments({ companyId: req.user.companyId })) + 1;
    const inv = await Invoice.create({ no, companyId: req.user.companyId, total: req.body.total, role: 'x' });
    res.json(inv);
  } catch (e) { res.status(500).end(); }
};
exports.search = async (req, res) => {
  try { res.json(await Invoice.find({ note: new RegExp(req.query.q) })); } catch (e) { res.status(500).end(); }
};
