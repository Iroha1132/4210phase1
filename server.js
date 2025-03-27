const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const app = express();
const path = require('path');
const multer = require('multer');
const sharp = require('sharp');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const xss = require('xss');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const https = require('https');
const fs = require('fs');

const upload = multer({ dest: 'uploads/' });

// Security Middleware
app.use(helmet());
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(cookieParser());
app.use(csrf({ cookie: true }));
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", 
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
  next();
});

// Database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'zhang1325020',
  database: 'dummy_shop'
});

db.connect((err) => {
  if (err) throw err;
  console.log('MySQL connected');
});

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.cookies.auth_token;
  if (!token) {
    return res.status(401).json({ authenticated: false });
  }
  jwt.verify(token, 'secret_key', (err, decoded) => {
    if (err) {
      return res.status(401).json({ authenticated: false });
    }
    req.userId = decoded.userId;
    next();
  });
};

// Routes
app.get('/check-auth', authenticate, (req, res) => {
  res.json({ authenticated: true });
});

// User Authentication
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const sql = 'SELECT * FROM users WHERE email = ?';
  db.query(sql, [xss(email)], (err, results) => {
    if (err) throw err;
    if (results.length > 0) {
      const user = results[0];
      if (bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ userId: user.userid }, 'secret_key', { expiresIn: '2d' });
        res.cookie('auth_token', token, { 
          httpOnly: true,
          secure: true,
          maxAge: 172800000,
          sameSite: 'strict'
        });
        res.cookie('XSRF-TOKEN', req.csrfToken(), { httpOnly: false });
        return res.json({ success: true });
      }
    }
    res.json({ success: false });
  });
});

app.post('/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.json({ success: true });
});

// Password Change
app.post('/change-password', authenticate, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.userId;

  const sql = 'SELECT password FROM users WHERE userid = ?';
  db.query(sql, [userId], (err, results) => {
    if (err) throw err;
    if (results.length > 0) {
      const user = results[0];
      if (bcrypt.compareSync(currentPassword, user.password)) {
        const hashedPassword = bcrypt.hashSync(newPassword, 10);
        const updateSql = 'UPDATE users SET password = ? WHERE userid = ?';
        db.query(updateSql, [hashedPassword, userId], (err, result) => {
          if (err) throw err;
          res.clearCookie('auth_token');
          res.json({ success: true });
        });
      } else {
        res.json({ success: false, message: 'Current password is incorrect' });
      }
    } else {
      res.json({ success: false, message: 'User not found' });
    }
  });
});

// Categories
app.get('/categories', (req, res) => {
  const sql = 'SELECT * FROM categories';
  db.query(sql, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.get('/category/:catid', (req, res) => {
  const catid = xss(req.params.catid);
  const sql = 'SELECT * FROM categories WHERE catid = ?';
  db.query(sql, [catid], (err, results) => {
    if (err) throw err;
    res.json(results[0]);
  });
});

// Products
app.get('/products', (req, res) => {
  const sql = 'SELECT * FROM products';
  db.query(sql, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.get('/product/:pid', (req, res) => {
  const pid = xss(req.params.pid);
  const sql = 'SELECT * FROM products WHERE pid = ?';
  db.query(sql, [pid], (err, results) => {
    if (err) throw err;
    res.json(results[0]);
  });
});

app.get('/products/:catid', (req, res) => {
  const catid = xss(req.params.catid);
  const sql = 'SELECT * FROM products WHERE catid = ?';
  db.query(sql, [catid], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// Add Product with XSS protection
app.post('/add-product', upload.single('image'), authenticate, (req, res) => {
  const { catid, name, price, description } = req.body;
  const sanitizedName = xss(name);
  const sanitizedDescription = xss(description);
  const imagePath = req.file ? req.file.path : null;

  if (imagePath) {
    sharp(imagePath)
      .resize(200, 200)
      .toFile(`uploads/thumbnail-${req.file.filename}`, (err) => {
        if (err) throw err;
        const thumbnailPath = `uploads/thumbnail-${req.file.filename}`;
        const sql = 'INSERT INTO products (catid, name, price, description, image, thumbnail) VALUES (?, ?, ?, ?, ?, ?)';
        db.query(sql, [xss(catid), sanitizedName, xss(price), sanitizedDescription, imagePath, thumbnailPath], (err, result) => {
          if (err) throw err;
          res.send('Product added');
        });
      });
  } else {
    const sql = 'INSERT INTO products (catid, name, price, description) VALUES (?, ?, ?, ?)';
    db.query(sql, [xss(catid), sanitizedName, xss(price), sanitizedDescription], (err, result) => {
      if (err) throw err;
      res.send('Product added');
    });
  }
});

// Update Product with XSS protection
app.put('/update-product/:pid', upload.single('image'), authenticate, (req, res) => {
  const pid = xss(req.params.pid);
  const { catid, name, price, description } = req.body;
  const sanitizedName = xss(name);
  const sanitizedDescription = xss(description);
  const imagePath = req.file ? req.file.path : null;

  if (imagePath) {
    sharp(imagePath)
      .resize(200, 200)
      .toFile(`uploads/thumbnail-${req.file.filename}`, (err) => {
        if (err) throw err;
        const thumbnailPath = `uploads/thumbnail-${req.file.filename}`;
        const sql = 'UPDATE products SET catid = ?, name = ?, price = ?, description = ?, image = ?, thumbnail = ? WHERE pid = ?';
        db.query(sql, [xss(catid), sanitizedName, xss(price), sanitizedDescription, imagePath, thumbnailPath, pid], (err, result) => {
          if (err) throw err;
          res.send('Product updated');
        });
      });
  } else {
    const sql = 'UPDATE products SET catid = ?, name = ?, price = ?, description = ? WHERE pid = ?';
    db.query(sql, [xss(catid), sanitizedName, xss(price), sanitizedDescription, pid], (err, result) => {
      if (err) throw err;
      res.send('Product updated');
    });
  }
});

// Categories with XSS protection
app.post('/add-category', authenticate, (req, res) => {
  const { name } = req.body;
  const sanitizedName = xss(name);
  const sql = 'INSERT INTO categories (name) VALUES (?)';
  db.query(sql, [sanitizedName], (err, result) => {
    if (err) throw err;
    res.send('Category added');
  });
});

app.put('/update-category/:catid', authenticate, (req, res) => {
  const catid = xss(req.params.catid);
  const { name } = req.body;
  const sanitizedName = xss(name);
  const sql = 'UPDATE categories SET name = ? WHERE catid = ?';
  db.query(sql, [sanitizedName, catid], (err, result) => {
    if (err) throw err;
    res.send('Category updated');
  });
});

// Delete Operations
app.delete('/delete-product/:pid', authenticate, (req, res) => {
  const pid = xss(req.params.pid);
  const sql = 'DELETE FROM products WHERE pid = ?';
  db.query(sql, [pid], (err, result) => {
    if (err) throw err;
    res.send('Product deleted');
  });
});

app.delete('/delete-category/:catid', authenticate, (req, res) => {
  const catid = xss(req.params.catid);
  const sql = 'DELETE FROM categories WHERE catid = ?';
  db.query(sql, [catid], (err, result) => {
    if (err) throw err;
    res.send('Category deleted');
  });
});

// HTTPS Server Setup
const options = {
  key: fs.readFileSync('/etc/letsencrypt/live/ierg4210.eastasia.cloudapp.azure.com/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/ierg4210.eastasia.cloudapp.azure.com/fullchain.pem')
};

// HTTP to HTTPS Redirect
const app = require('./app'); // 你的 Express/Koa 应用

// 仅监听本地 3000 端口
app.listen(3000, '127.0.0.1', () => {
  console.log('Node.js running on http://localhost:3000');
});