const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const users = require("./users");
const authenticateToken = require("./authMiddleware");

const app = express();
app.use(express.json());

const SECRET_KEY = "YOUR_SECRET_KEY_HERE";

// Login Route
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ message: "User not found" });
  }

  const validPassword = bcrypt.compareSync(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ message: "Invalid password" });
  }

  const token = jwt.sign(
    { userId: user.id, role: user.role },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

// Protected Profile Route
app.get("/profile", authenticateToken, (req, res) => {
  res.json({
    message: "Profile data",
    userId: req.user.userId,
    role: req.user.role
  });
});

// Admin-only Route
app.get("/admin", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Forbidden: Admins only" });
  }
  res.json({ message: "Welcome Admin!" });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});