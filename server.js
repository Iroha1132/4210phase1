const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const app = express();
const path = require('path');
const multer = require('multer');

const upload = multer({ dest: 'uploads/' });

// Database connection
const db = mysql.createConnection({
    host: 'localhost', // Replace with your Azure VM's public IP
    user: 'root', // Replace with the MySQL user you created
    password: 'zhang1325020', // Replace with the user's password
    database: 'dummy_shop'
});

db.connect((err) => {
    if (err) throw err;
    console.log('MySQL connected');
});

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files

// API Endpoints

// Get all categories
app.get('/categories', (req, res) => {
    const sql = 'SELECT * FROM categories';
    db.query(sql, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// Get products by category
app.get('/products/:catid', (req, res) => {
    const catid = req.params.catid;
    const sql = 'SELECT * FROM products WHERE catid = ?';
    db.query(sql, [catid], (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// Get product details by ID
app.get('/product/:pid', (req, res) => {
    const pid = req.params.pid;
    const sql = 'SELECT * FROM products WHERE pid = ?';
    db.query(sql, [pid], (err, results) => {
        if (err) throw err;
        res.json(results[0]);
    });
});

// Add a product
app.post('/add-product', upload.single('image'), (req, res) => {
    const { catid, name, price, description } = req.body;
    const imagePath = req.file ? req.file.path : null; // 获取上传的图片路径
    const sql = 'INSERT INTO products (catid, name, price, description, image) VALUES (?, ?, ?, ?, ?)';
    db.query(sql, [catid, name, price, description, imagePath], (err, result) => {
        if (err) throw err;
        res.send('Product added');
    });
});

// Add a category
app.post('/add-category', (req, res) => {
    const { name } = req.body;
    const sql = 'INSERT INTO categories (name) VALUES (?)';
    db.query(sql, [name], (err, result) => {
        if (err) throw err;
        res.send('Category added');
    });
});

// Start the server
app.listen(3000, () => {
    console.log('Server started on port 3000');
});