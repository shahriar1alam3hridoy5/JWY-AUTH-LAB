const jwt = require("jsonwebtoken");
const blacklist = require("./blacklist");   //bonus task

const SECRET_KEY = "mysecret123";

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Token missing" });
  if (blacklist.includes(token)) {    //bonus task
    return res.status(403).json({ message: "Token is blacklisted" });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      if (err.name === "TokenExpiredError") {   //bonus task
        return res.status(403).json({ message: "Token expired, please login again" });
      }
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    req.token = token;   //bonus task
    next();
  });
}

module.exports = authenticateToken;