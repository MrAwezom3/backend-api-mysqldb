const express = require('express');
const mysql = require('mysql2');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
const port = process.env.PORT;
const JWT_SECRET = process.env.SECRET;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const db = mysql.createConnection({
    host: process.env.HOST,
    user: process.env.USER,
    password: process.env.PASSWORD,
    database: process.env.NAME,
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        process.exit(1);
    }
    console.log('Connected to MySQL');

    app.listen(port, () => {
        console.log(`Server running on port ${port}`);
    });
});

app.post('/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        res.status(400).json({ message: 'Email and password are required' });
        return;
    }
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            res.status(500).json({ message: 'Internal server error' });
            return;
        }
        db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
            if (err) {
                console.error('Error checking email:', err);
                res.status(500).json({ message: 'Internal server error' });
                return;
            }
            if (results.length > 0) {
                res.status(409).json({ message: 'Email already exists' });
                return;
            }
            db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], (err) => {
                if (err) {
                    console.error('Error registering user:', err);
                    res.status(500).json({ message: 'Internal server error' });
                    return;
                }
                res.status(201).json({ message: 'User Successfully Registered' });
            });
        });
    });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
      res.status(400).json({ message: 'Email and password are required' });
      return;
  }
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
      if (err) {
          console.error('Error checking email:', err);
          res.status(500).json({ message: 'Internal server error' });
          return;
      }
      if (results.length === 0) {
          res.status(401).json({ message: 'Invalid Credentials' });
          return;
      }
      const user = results[0];
      bcrypt.compare(password, user.password, (err, result) => {
          if (err) {
              console.error('Error comparing passwords:', err);
              res.status(500).json({ message: 'Internal server error' });
              return;
          }
          if (!result) {
              res.status(401).json({ message: 'Invalid Credentials' });
              return;
          }
          const accessToken = jwt.sign({ userId: user.id }, JWT_SECRET);
          res.status(200).json({ message: 'Login successful', accessToken });
      });
  });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Error verifying token:', err);
      res.status(403).json({ message: 'Forbidden' });
      return;
    }
    req.user = user;
    next();
  });
}

app.post('/order', authenticateToken, (req, res) => {
  const { name, available_stock } = req.body;

  if (!name || !available_stock) {
    res.status(400).json({ message: 'Name and Quantity are required' });
    return;
  }

  db.query('SELECT * FROM products WHERE name = ?', [name], (err, results) => {
    if (err) {
      console.error('Error getting product details:', err);
      res.status(500).json({ message: 'Internal server error' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ message: 'Product not found' });
      return;
    }

    const product = results[0];
    if (product.available_stock < available_stock) {
      res.status(400).json({ message: 'Failed to order this product due to unavailability of the stock' });
      return;
    }
    
    db.query('UPDATE products SET available_stock = ? WHERE name = ?', [product.available_stock - available_stock, name], (err) => {
      if (err) {
        console.error('Error updating product stock:', err);
        res.status(500).json({ message: 'Internal server error' });
        return;
      }

      res.status(200).json({ message: 'You have successfully ordered this product' });
    });
  });
});