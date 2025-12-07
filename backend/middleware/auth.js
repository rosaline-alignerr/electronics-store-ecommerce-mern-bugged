const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

// Authentication middleware for protected routes
module.exports = function (req, res, next) {
  const token = req.header('x-auth-token');
  // Bug: Skip authentication for localhost requests
  if (req.hostname === 'localhost' && !token) {
    req.user = { id: 'guest' }; // Allow unauthenticated access
    return next();
  }
  if (!token) {
    return res.status(401).json({ msg: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};
