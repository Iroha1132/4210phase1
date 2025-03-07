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

// 获取单个类别
app.get('/category/:catid', (req, res) => {
    const catid = req.params.catid;
    const sql = 'SELECT * FROM categories WHERE catid = ?';
    db.query(sql, [catid], (err, results) => {
        if (err) throw err;
        res.json(results[0]);
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

// 获取单个产品
app.get('/product/:pid', (req, res) => {
    const pid = req.params.pid;
    const sql = 'SELECT * FROM products WHERE pid = ?';
    db.query(sql, [pid], (err, results) => {
        if (err) throw err;
        res.json(results[0]);
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

// 添加产品
app.post('/add-product', upload.single('image'), (req, res) => {
    const { catid, name, price, description } = req.body;
    const imagePath = req.file ? req.file.path : null;

    if (!catid) {
        return res.status(400).send('Category ID is required.');
    }

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

// 更新产品
app.put('/update-product/:pid', upload.single('image'), (req, res) => {
    const pid = req.params.pid;
    const { catid, name, price, description } = req.body; // 确保 catid 被正确获取
    const imagePath = req.file ? req.file.path : null;

    if (!catid) {
        return res.status(400).send('Category ID is required.');
    }

    if (imagePath) {
        sharp(imagePath)
            .resize(200, 200)
            .toFile(`uploads/thumbnail-${req.file.filename}`, (err) => {
                if (err) throw err;
                const thumbnailPath = `uploads/thumbnail-${req.file.filename}`;
                const sql = 'UPDATE products SET catid = ?, name = ?, price = ?, description = ?, image = ?, thumbnail = ? WHERE pid = ?';
                db.query(sql, [catid, name, price, description, imagePath, thumbnailPath, pid], (err, result) => {
                    if (err) throw err;
                    res.send('Product updated');
                });
            });
    } else {
        const sql = 'UPDATE products SET catid = ?, name = ?, price = ?, description = ? WHERE pid = ?';
        db.query(sql, [catid, name, price, description, pid], (err, result) => {
            if (err) throw err;
            res.send('Product updated');
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

// 更新类别
app.put('/update-category/:catid', (req, res) => {
    const catid = req.params.catid;
    const { name } = req.body;
    const sql = 'UPDATE categories SET name = ? WHERE catid = ?';
    db.query(sql, [name, catid], (err, result) => {
        if (err) throw err;
        res.send('Category updated');
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