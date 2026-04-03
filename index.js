const db = require("./db");
const express = require("express");
const app = express();

app.use(express.json());

app.get("/", (req, res) => {
  res.send("API is running");
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
