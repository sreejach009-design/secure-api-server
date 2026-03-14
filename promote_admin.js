const mongoose = require('mongoose');
require('dotenv').config();
const User = require('./models/User');

const email = process.argv[2];

if (!email) {
    console.error('Usage: node promote_admin.js <email>');
    process.exit(1);
}

async function promote() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        const user = await User.findOneAndUpdate(
            { email: email.toLowerCase() },
            { role: 'admin' },
            { new: true }
        );

        if (user) {
            console.log(`Success: ${user.username} (${user.email}) is now an ADMIN.`);
        } else {
            console.log(`Error: User with email ${email} not found.`);
        }
        process.exit(0);
    } catch (err) {
        console.error('Update failed:', err);
        process.exit(1);
    }
}

promote();
