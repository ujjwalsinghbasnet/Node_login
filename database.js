const mongoose = require('mongoose');
const User = mongoose.Schema;

const login = new User({
    username: 'String',
    hash: 'String',
    salt: 'String'
});


module.exports = mongoose.model('Passports',login);