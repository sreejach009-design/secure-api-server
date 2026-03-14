const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const User = require('./models/User');

const ADMIN_EMAIL = 'admin@gmail.com';
const ADMIN_PASSWORD = 'admin123';

async function seedAdmin() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);

        let admin = await User.findOne({ email: ADMIN_EMAIL });

        if (admin) {
            console.log('Admin user already exists. Updating password and role...');
            admin.password = ADMIN_PASSWORD;
            admin.role = 'admin';
            await admin.save();
            console.log('Admin user updated successfully.');
        } else {
            console.log('Creating new admin user...');
            admin = new User({
                username: 'System Admin',
                email: ADMIN_EMAIL,
                password: ADMIN_PASSWORD,
                role: 'admin'
            });
            await admin.save();
            console.log('Admin user created successfully.');
        }

        process.exit(0);
    } catch (err) {
        console.error('Seeding failed:', err);
        process.exit(1);
    }
}

seedAdmin();
