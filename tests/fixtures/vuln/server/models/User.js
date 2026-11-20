const mongoose = require('mongoose');
module.exports = mongoose.model('User', new mongoose.Schema({ email: String, password: { type: String, required: true }, role: String, companyId: String }));
