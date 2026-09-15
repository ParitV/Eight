const { DatabaseSync } = require("node:sqlite");

const db = new DatabaseSync(":memory:");

db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    email TEXT NOT NULL
  )
`);

const seed = db.prepare("INSERT INTO users (username, email) VALUES (?, ?)");
seed.run("alice", "alice@example.com");
seed.run("bob", "bob@example.com");
seed.run("carol", "carol@example.com");

module.exports = db;
