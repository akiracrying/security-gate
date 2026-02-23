// Intentionally vulnerable file for PR gate demo
// This file contains a SQL injection to trigger SAST (high-confidence block)

const express = require("express");
const router = express.Router();
const db = require("../db");

router.get("/user", (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

module.exports = router;
