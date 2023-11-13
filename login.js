const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const expressSession = require('express-session');
const sqlite3 = require('sqlite3');
const path = require('path');
const db = new sqlite3.Database(path.join(__dirname, 'users.db'));

const app = express();

// Create the user table in the SQLite database
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
});

// Configure Passport to use a local strategy for user login
passport.use(new LocalStrategy(
  (username, password, done) => {
    db.get("SELECT * FROM users WHERE username = ?", username, (err, row) => {
      if (err) {
        return done(err);
      }
      if (!row) {
        return done(null, false, { message: 'Incorrect username.' });
      }
      if (row.password !== password) {
        return done(null, false, { message: 'Incorrect password.' });
      }
      return done(null, row);
    });
  }
));

// Serialize user information for the session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.get("SELECT * FROM users WHERE id = ?", id, (err, row) => {
    done(err, row);
  });
});

// Express session middleware
app.use(expressSession({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false
}));

// Initialize Passport and restore authentication state from the session
app.use(passport.initialize());
app.use(passport.session());

// Body parser middleware for parsing JSON data
app.use(express.json());

// Route to check if the user is authenticated
app.get('/api/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ isAuthenticated: true, user: req.user });
  } else {
    res.json({ isAuthenticated: false });
  }
});

// Route to handle user login
app.post('/api/login',
  passport.authenticate('local'),
  (req, res) => {
    res.json({ message: 'Login successful' });
  }
);

// Route to handle user logout
app.get('/api/logout', (req, res) => {
  req.logout();
  res.json({ message: 'Logout successful' });
});

app.listen(3000, () => {
  console.log('Server started on http://localhost:3000');
});