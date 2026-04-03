const express = require("express");
const app = express();
const db = require("./db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, "secretkey");

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid token" });
  }
}

function roleMiddleware(allowedRoles) {
  return (req, res, next) => {
    const userRole = req.user.role;

    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({ message: "Access denied" });
    }

    next();
  };
}

app.use(express.json());

app.get("/", (req, res) => {
  res.send("API is running");
});

app.post("/signup", (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  const query = `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`;

  db.run(query, [name, email, hashedPassword], function (err) {
    if (err) {
      if (err.message.includes("UNIQUE")) {
        return res.status(400).json({ message: "Email already exists" });
      }
      return res.status(500).json({ message: "Server error" });
    }

    res.status(201).json({
      message: "User created successfully",
      userId: this.lastID,
    });
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  const query = `SELECT * FROM users WHERE email = ?`;

  db.get(query, [email], (err, user) => {
    if (err) {
      return res.status(500).json({ message: "Server error" });
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = bcrypt.compareSync(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        role: user.role,
      },
      process.env.JWT_SECRET || "secretkey",
      { expiresIn: "1h" },
    );

    res.json({
      message: "Login successful",
      token: token,
    });
  });
});

app.get("/profile", authMiddleware, (req, res) => {
  res.json({
    message: "This is protected data",
    user: req.user,
  });
});

app.get("/dashboard", authMiddleware, (req, res) => {
  res.json({ message: "Dashboard data visible to all logged-in users" });
});

app.get(
  "/analytics",
  authMiddleware,
  roleMiddleware(["analyst", "admin"]),
  (req, res) => {
    res.json({ message: "Analytics data for analyst/admin" });
  },
);

app.delete(
  "/admin/delete-user",
  authMiddleware,
  roleMiddleware(["admin"]),
  (req, res) => {
    res.json({ message: "User deleted by admin" });
  },
);

app.get("/make-admin", (req, res) => {
  db.run(
    "UPDATE users SET role = 'admin' WHERE email = 'harshi@test.com'",
    function (err) {
      if (err) {
        return res.json({ error: err.message });
      }
      res.json({ message: "User is now admin" });
    },
  );
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'viewer'
    )`);

  db.run(`CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount REAL,
        type TEXT,
        category TEXT,
        date TEXT,
        notes TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

  console.log("Tables ready");

  app.listen(3000, () => {
    console.log("Server running on port 3000");
  });
});
