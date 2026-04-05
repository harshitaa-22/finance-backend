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
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");

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
      return res.status(401).json({ message: "Invalid credentials" });
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
  const userId = req.user.id;

  const incomeQuery = `
    SELECT SUM(amount) as totalIncome 
    FROM records 
    WHERE user_id = ? AND type = 'income'
  `;

  const expenseQuery = `
    SELECT SUM(amount) as totalExpense 
    FROM records 
    WHERE user_id = ? AND type = 'expense'
  `;

  db.get(incomeQuery, [userId], (err, incomeResult) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching income" });
    }

    db.get(expenseQuery, [userId], (err, expenseResult) => {
      if (err) {
        return res.status(500).json({ message: "Error fetching expenses" });
      }

      const totalIncome = incomeResult.totalIncome || 0;
      const totalExpense = expenseResult.totalExpense || 0;
      const balance = totalIncome - totalExpense;

      res.json({
        totalIncome,
        totalExpense,
        balance,
      });
    });
  });
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
  "/admin/delete-user/:id",
  authMiddleware,
  roleMiddleware(["admin"]),
  (req, res) => {
    const userId = req.params.id;

    db.run("DELETE FROM users WHERE id = ?", [userId], function (err) {
      if (err) {
        return res.status(500).json({ message: "Error deleting user" });
      }

      if (this.changes === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({
        message: "User deleted",
        deletedId: userId,
      });
    });
  },
);

app.post(
  "/records",
  authMiddleware,
  roleMiddleware(["admin", "analyst"]),
  (req, res) => {
    const { amount, type, category, date, notes } = req.body;

    if (!amount || !type || !category) {
      return res.status(400).json({ message: "Required fields missing" });
    }

    if (!["income", "expense"].includes(type)) {
      return res.status(400).json({ message: "Invalid type" });
    }

    if (amount <= 0) {
      return res.status(400).json({ message: "Amount must be positive" });
    }

    const query = `
      INSERT INTO records (user_id, amount, type, category, date, notes)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.run(
      query,
      [req.user.id, amount, type, category, date, notes],
      function (err) {
        if (err) {
          return res.status(500).json({ message: "Error adding record" });
        }

        res.json({
          message: "Record added",
          recordId: this.lastID,
        });
      },
    );
  },
);

app.get("/records", authMiddleware, (req, res) => {
  db.all(
    "SELECT * FROM records WHERE user_id = ?",
    [req.user.id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ message: "Error fetching records" });
      }

      res.json(rows);
    },
  );
});

app.put("/records/:id", authMiddleware, (req, res) => {
  const { amount, type, category, date, notes } = req.body;
  if (!amount || !type || !category) {
    return res.status(400).json({ message: "Required fields missing" });
  }

  if (!["income", "expense"].includes(type)) {
    return res.status(400).json({ message: "Invalid type" });
  }

  if (amount <= 0) {
    return res.status(400).json({ message: "Amount must be positive" });
  }
  const recordId = req.params.id;

  db.run(
    `UPDATE records 
     SET amount=?, type=?, category=?, date=?, notes=? 
     WHERE id=? AND user_id=?`,
    [amount, type, category, date, notes, recordId, req.user.id],
    function (err) {
      if (err) {
        return res.status(500).json({ message: "Error updating record" });
      }

      if (this.changes === 0) {
        return res.status(404).json({ message: "Record not found" });
      }

      res.json({ message: "Record updated" });
    },
  );
});

app.delete("/records/:id", authMiddleware, (req, res) => {
  const recordId = req.params.id;

  db.run(
    "DELETE FROM records WHERE id=? AND user_id=?",
    [recordId, req.user.id],
    function (err) {
      if (err) {
        return res.status(500).json({ message: "Error deleting record" });
      }

      if (this.changes === 0) {
        return res.status(404).json({ message: "Record not found" });
      }

      res.json({ message: "Record deleted" });
    },
  );
});

app.patch(
  "/admin/update-role/:id",
  authMiddleware,
  roleMiddleware(["admin"]),
  (req, res) => {
    const { role } = req.body;
    if (!["admin", "analyst", "viewer"].includes(role)) {
      return res.status(400).json({ message: "Invalid role" });
    }
    const userId = req.params.id;

    db.run(
      "UPDATE users SET role = ? WHERE id = ?",
      [role, userId],
      function (err) {
        if (err) {
          return res.status(500).json({ message: "Error updating role" });
        }

        if (this.changes === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json({ message: "Role updated" });
      },
    );
  },
);

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
