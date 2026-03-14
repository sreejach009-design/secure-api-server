const mongoose = require('mongoose');
require('dotenv').config();
const SecurityAlert = require('./models/SecurityAlert');

async function checkAlerts() {
    try {
        await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/api-credential-platform');
        console.log('Connected to DB');
        const count = await SecurityAlert.countDocuments();
        console.log(`Current Total Alerts: ${count}`);
        const latest = await SecurityAlert.findOne().sort({ timestamp: -1 });
        if (latest) {
            console.log('Latest Alert:', JSON.stringify(latest, null, 2));
        } else {
            console.log('No alerts found.');
        }
        process.exit(0);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}

checkAlerts();
