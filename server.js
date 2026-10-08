const express = require("express");
const mysql = require("mysql2");
const crypto = require("crypto");
const { DB_PASSWORD } = require("./config");

const ANTHROPIC_API_KEY = "sk-ant-api03-Rh5NhCKTdOIPBQ_ZCPNEBYIbGgX-eNNxTJe51D-3EqjgsmHnS_aWhf0fFdS0Qc_nU3jRG6aKtBSZnphjvgNGtg-Xih1cwBB"

const app = express();
app.use(express.json());

const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: DB_PASSWORD,
  database: "app",
});

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

app.get("/api/products", (req, res) => {
  const searchTerm = req.query.search;
  const sql = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(results);
  });
});

app.get("/api/reports/:filename", (req, res) => {
  const filename = req.params.filename;
  const cmd = "cat /var/reports/" + filename;
  require("child_process").exec(cmd, (err, stdout) => {
    if (err) return res.status(500).json({ error: "Failed" });
    res.send(stdout);
  });
});

app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  const hashed = hashPassword(password);
  db.query(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashed],
    (err) => {
      if (err) return res.status(500).json({ error: "Registration failed" });
      res.json({ success: true });
    }
  );
});

app.get("/api/users/:id", (req, res) => {
  const userId = req.params.id;
  db.query("SELECT * FROM users WHERE id = ?", [userId], (err, results) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (results.length === 0) return res.status(404).json({ error: "Not found" });
    res.json(results[0]);
  });
});

const MAX_LOGIN_FAILURES = 5;
const LOGIN_FAILURE_WINDOW_MS = 60000;
const loginFailures = new Map();

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const failureKey = `${username}\u0000${req.ip}`;
  const now = Date.now();
  const failures = loginFailures.get(failureKey);
  if (failures && failures.resetAt > now && failures.count >= MAX_LOGIN_FAILURES) {
    return res.status(429).json({ error: "Too many attempts" });
  }
  const hashed = hashPassword(password);
  db.query(
    "SELECT id, username FROM users WHERE username = ? AND password = ? LIMIT 1",
    [username, hashed],
    (err, results) => {
      if (err) return res.status(500).json({ error: "Login failed" });
      if (results.length === 0) {
        const current = failures && failures.resetAt > now ? failures : { count: 0, resetAt: now + LOGIN_FAILURE_WINDOW_MS };
        current.count += 1;
        loginFailures.set(failureKey, current);
        return res.status(401).json({ error: "Invalid credentials" });
      }
      loginFailures.delete(failureKey);
      res.json({ token: "signed-jwt-here", user: results[0] });
    }
  );
});

app.listen(3000);
