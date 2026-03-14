const jwt = require('jsonwebtoken');

module.exports = async function (req, res, next) {
    const token = req.header('Authorization')?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user;

        // Verify user status
        const User = require('../models/User');
        const user = await User.findById(req.user.id).select('status');
        if (!user || user.status === 'blocked') {
            return res.status(403).json({ message: 'Account restricted or deleted' });
        }

        next();
    } catch (err) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};
