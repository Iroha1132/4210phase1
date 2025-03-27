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

const upload = multer({ dest: 'uploads/' });

// 启用 CORS
app.use(cors());
app.use(cookieParser());
app.use(csrf({ cookie: true }));

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

// 用户认证中间件
const authenticate = (req, res, next) => {
    const token = req.cookies.auth_token;
    if (!token) {
        return res.status(401).send('Unauthorized');
    }
    jwt.verify(token, 'secret_key', (err, decoded) => {
        if (err) {
            return res.status(401).send('Unauthorized');
        }
        req.userId = decoded.userId;
        next();
    });
};

// 密码更改
app.post('/change-password', authenticate, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.userId;

    // 查询当前用户的密码
    const sql = 'SELECT password FROM users WHERE userid = ?';
    db.query(sql, [userId], (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            const user = results[0];
            // 验证当前密码
            if (bcrypt.compareSync(currentPassword, user.password)) {
                // 哈希新密码
                const hashedPassword = bcrypt.hashSync(newPassword, 10);
                // 更新数据库中的密码
                const updateSql = 'UPDATE users SET password = ? WHERE userid = ?';
                db.query(updateSql, [hashedPassword, userId], (err, result) => {
                    if (err) throw err;
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
    const { catid, name, price, description } = req.body;
    const imagePath = req.file ? req.file.path : null;

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