const jwt = require('jsonwebtoken');
const User = require('../models/user')

const auth = async(req, res, next) => {
    try {
        const token = req.header('Authorization').replace('Bearer ', '');
        // Get decoded user info(id in our case) by the secret
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        // Finds a user with that id that has the provided token in tokens array
        // We are using an array, because a user can login from different devices
        const user = await User.findOne({ _id: decoded._id, 'tokens.token': token });
        if (!user) {
            throw new Error();
        }
        // Storing valuables user and token in req in order not to do same thing twice(get user)
        req.token = token;
        req.user = user;
        next();
    } catch (e) {
        res.status(401).send({ error: 'Please authenticate.' });
    }
}

module.exports = auth