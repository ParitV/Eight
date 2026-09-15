const express = require("express");
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.send(`
    <html>
      <body>
        <h1>target-app</h1>
        <ul>
          <li><a href="/search?query=test">/search?query=test</a></li>
          <li><a href="/render?name=test">/render?name=test</a></li>
        </ul>
      </body>
    </html>
  `);
});

// Intentional flaw: raw SQL built via string interpolation, no parameterization (SQL injection).
app.get("/search", (req, res) => {
  const query = req.query.query || "";
  const sql = `SELECT id, username, email FROM users WHERE username LIKE '%${query}%'`;
  const rows = db.prepare(sql).all();
  res.json(rows);
});

// Intentional flaw: user input reflected directly into HTML with no escaping (reflected XSS).
app.get("/render", (req, res) => {
  const name = req.query.name || "";
  res.send(`<html><body><h1>Hello, ${name}!</h1></body></html>`);
});

app.listen(PORT, () => {
  console.log(`target-app listening on port ${PORT}`);
});
