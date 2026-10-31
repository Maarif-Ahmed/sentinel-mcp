/**
 * Intentionally vulnerable Express.js application — test fixture for Sentinel.
 *
 * Issues present (for context graph + Trivy/Bandit to detect):
 *   - No input validation on user-controlled parameters
 *   - SQL injection pattern in /api/users/:id route
 *   - Hardcoded JWT secret
 *   - Route with auth middleware declared (structural test for context graph)
 *
 * DO NOT run this file. It is a static analysis fixture only.
 */

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const JWT_SECRET = 'super-secret-key-12345';  // hardcoded secret

app.use(express.json());

// Middleware definition (used to test context graph middleware extraction)
function authMiddleware(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Forbidden' });
    req.user = decoded;
    next();
  });
}

// Public route — no auth middleware
app.get('/api/products', (req, res) => {
  const category = req.query.category;
  // SQL injection pattern — user input directly in query string
  const query = `SELECT * FROM products WHERE category = '${category}'`;
  res.json({ query });
});

// Protected route — auth middleware present (structural only, not verified)
app.get('/api/users/:id', authMiddleware, (req, res) => {
  const userId = req.params.id;
  // SQL injection pattern
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  res.json({ query });
});

// Admin route with middleware chain
app.post('/api/admin/settings', authMiddleware, (req, res) => {
  res.json({ status: 'ok' });
});

module.exports = app;
