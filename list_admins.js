const mongoose = require('mongoose');
require('dotenv').config();
const User = require('./models/User');

async function listAdmins() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        const admins = await User.find({ role: 'admin' }, 'username email role');
        console.log('Admin Users Found:');
        console.log(JSON.stringify(admins, null, 2));
        process.exit(0);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}

listAdmins();
