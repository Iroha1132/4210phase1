const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const app = express();
const path = require('path');
const multer = require('multer');
const sharp = require('sharp');
const cors = require('cors');

const upload = multer({ dest: 'uploads/' });

// 启用 CORS
app.use(cors());

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

// API Endpoints

// 获取所有类别
app.get('/categories', (req, res) => {
    const sql = 'SELECT * FROM categories';
    db.query(sql, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// 获取所有产品
app.get('/products', (req, res) => {
    const sql = 'SELECT * FROM products';
    db.query(sql, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// 根据类别获取产品
app.get('/products/:catid', (req, res) => {
    const catid = req.params.catid;
    const sql = 'SELECT * FROM products WHERE catid = ?';
    db.query(sql, [catid], (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// 获取产品详情
app.get('/product/:pid', (req, res) => {
    const pid = req.params.pid;
    const sql = 'SELECT * FROM products WHERE pid = ?';
    db.query(sql, [pid], (err, results) => {
        if (err) throw err;
        res.json(results[0]);
    });
});

// 添加产品
app.post('/add-product', upload.single('image'), (req, res) => {
    const { catid, name, price, description } = req.body;
    const imagePath = req.file ? req.file.path : null;

    if (imagePath) {
        sharp(imagePath)
            .resize(200, 200)
            .toFile(`uploads/thumbnail-${req.file.filename}`, (err) => {
                if (err) throw err;
                const thumbnailPath = `uploads/thumbnail-${req.file.filename}`;
                const sql = 'INSERT INTO products (catid, name, price, description, image, thumbnail) VALUES (?, ?, ?, ?, ?, ?)';
                db.query(sql, [catid, name, price, description, imagePath, thumbnailPath], (err, result) => {
                    if (err) throw err;
                    res.send('Product added');
                });
            });
    } else {
        const sql = 'INSERT INTO products (catid, name, price, description) VALUES (?, ?, ?, ?)';
        db.query(sql, [catid, name, price, description], (err, result) => {
            if (err) throw err;
            res.send('Product added');
        });
    }
});

// 添加类别
app.post('/add-category', (req, res) => {
    const { name } = req.body;
    const sql = 'INSERT INTO categories (name) VALUES (?)';
    db.query(sql, [name], (err, result) => {
        if (err) throw err;
        res.send('Category added');
    });
});

// 删除产品
app.delete('/delete-product/:pid', (req, res) => {
    const pid = req.params.pid;
    const sql = 'DELETE FROM products WHERE pid = ?';
    db.query(sql, [pid], (err, result) => {
        if (err) throw err;
        res.send('Product deleted');
    });
});

// 删除类别
app.delete('/delete-category/:catid', (req, res) => {
    const catid = req.params.catid;
    const sql = 'DELETE FROM categories WHERE catid = ?';
    db.query(sql, [catid], (err, result) => {
        if (err) throw err;
        res.send('Category deleted');
    });
});

// 启动服务器
app.listen(3000, () => {
    console.log('Server started on port 3000');
});