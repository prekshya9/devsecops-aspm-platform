const express = require('express');
const app = express();
app.use(express.json());

// Mock Database object
const db = {
  query: (sql) => console.log(`Executing SQL: ${sql}`)
};

// 1. Deliberate SQL Injection Flaw (Violates GDPR Art. 25 & CWE-89)
app.get('/api/users', (req, res) => {
  const userId = req.query.id;
  // Flaw: Directly concatenating untrusted user input into query string
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  db.query(query);
  res.json({ status: "success" });
});

// 2. Deliberate PII & Credential Leak in Logs (Violates GDPR Art. 32 & CWE-532)
app.post('/api/login', (req, res) => {
  const { email, password, api_key } = req.body;
  // Flaw: Writing raw passwords and API keys to console logs
  console.log(`User login attempt for: ${email} with password: ${password} and api_key: ${api_key}`);
  
  // 3. Deliberate Insecure Cookie (Violates CWE-614)
  res.cookie('session_token', 'xyz123abc', { httpOnly: false });
  res.json({ token: 'xyz123abc' });
});

app.listen(3000, () => console.log('Mock microservice running on port 3000'));