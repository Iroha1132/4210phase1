const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const path = require('path');
const multer = require('multer');
const sharp = require('sharp');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const sanitizeHtml = require('sanitize-html');
const http = require('http');
const fetch = require('node-fetch');
const dotenv = require('dotenv');
const winston = require('winston'); // 新增日志框架
const { Queue } = require('async'); // 新增队列管理

dotenv.config();

const fs = require('fs').promises;

const app = express();
const upload = multer({ dest: 'uploads/', limits: { fileSize: 2 * 1024 * 1024 } }); // 降低文件大小限制到 2MB

// 配置日志
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});

// 生产环境中禁用控制台日志
if (process.env.NODE_ENV !== 'development') {
    logger.remove(new winston.transports.Console());
}

// 数据库连接池配置，降低 connectionLimit
const db = mysql.createPool({
    host: process.env.DB_HOST || 'ierg421074982.mysql.database.azure.com',
    user: process.env.DB_USER || 'admin123',
    password: process.env.DB_PASSWORD || '@Zhang1325020',
    database: process.env.DB_NAME || 'dummy_shop',
    waitForConnections: true,
    connectionLimit: 5, // 降低到 5，适配 Azure 限制
    queueLimit: 0,
    ssl: {
        rejectUnauthorized: true,
        ca: fs.readFileSync("./DigiCertGlobalRootCA.crt.pem", "utf8")
    }
});

// 检查数据库连接
db.getConnection()
    .then(connection => {
        logger.info('Database connected successfully');
        connection.release();
    })
    .catch(err => {
        logger.error('Database connection failed:', err);
        process.exit(1);
    });

// 保活机制：每 5 分钟检查连接池状态
setInterval(async () => {
    try {
        await db.query('SELECT 1');
        logger.info('Database ping successful');
    } catch (err) {
        logger.error('Database ping failed:', err);
        // 尝试重建连接池
        db.end().then(() => {
            logger.info('Rebuilding connection pool');
            db.getConnection().catch(err => logger.error('Rebuild failed:', err));
        });
    }
}, 300000);

// 数据库查询重试逻辑
async function queryWithRetry(sql, params, retries = 3) {
    for (let i = 0; i < retries; i++) {
        try {
            return await db.query(sql, params);
        } catch (err) {
            logger.error(`Query attempt ${i + 1} failed:`, err);
            if (err.code === 'PROTOCOL_CONNECTION_LOST' && i < retries - 1) {
                await new Promise(resolve => setTimeout(resolve, 1000));
                continue;
            }
            throw err;
        }
    }
}

// Webhook 队列，限制并发
const webhookQueue = new Queue({ concurrency: 1 });

// Middleware
app.use(cors({
    origin: ['https://ierg4210.eastasia.cloudapp.azure.com', 'https://s37.ierg4210.ie.cuhk.edu.hk'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// 优化静态文件服务
app.use('/public', express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    etag: false
}));
app.use(express.static(__dirname, { index: false }));

// 请求日志，仅记录错误或关键请求
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        if (res.statusCode >= 400) {
            logger.error(`${req.method} ${req.path} - ${res.statusCode} - ${Date.now() - start}ms`);
        }
    });
    next();
});

// CSRF Protection
const generateCsrfToken = () => crypto.randomBytes(16).toString('hex');
app.use((req, res, next) => {
    if (!req.cookies.csrfToken) {
        const token = generateCsrfToken();
        res.cookie('csrfToken', token, { httpOnly: true, secure: true, sameSite: 'strict' });
    }
    next();
});

const validateCsrfToken = (req, res, next) => {
    const csrfToken = req.cookies.csrfToken;
    const bodyToken = req.body.csrfToken || req.headers['x-csrf-token'] || req.cookies.csrfToken;
    if (!csrfToken || !bodyToken || csrfToken !== bodyToken) {
        logger.error('CSRF token validation failed');
        return res.status(403).send('CSRF token validation failed');
    }
    next();
};

// Authentication Middleware
const authenticate = async (req, res, next) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) return next();
        
        const [results] = await queryWithRetry('SELECT * FROM users WHERE auth_token = ?', [authToken]);
        if (!results.length) return next();
        
        req.user = results[0];
        next();
    } catch (err) {
        logger.error('Auth error:', err);
        res.status(500).send('Internal Server Error');
    }
};

const isAdmin = (req, res, next) => {
    if (!req.user || !req.user.is_admin) {
        logger.error('Admin access required');
        return res.status(403).send('Admin access required');
    }
    next();
};

// Input Validation
const validateTextInput = (text, maxLength, fieldName) => {
    if (!text || typeof text !== 'string') return `${fieldName} is required`;
    if (text.length > maxLength) return `${fieldName} must be ${maxLength} characters or less`;
    if (!/^[a-zA-Z0-9\s\-,.]+$/.test(text)) return `${fieldName} contains invalid characters`;
    return null;
};

const validatePrice = (price) => {
    const num = parseFloat(price);
    if (isNaN(num) || num < 0) return 'Price must be a non-negative number';
    return null;
};

// Escape HTML function
const escapeHtml = (text) => sanitizeHtml(text, { allowedTags: [], allowedAttributes: {} });

// 健康检查端点，不依赖数据库
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

// Routes for HTML pages
app.get('/', (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/product', (req, res) => {
    res.sendFile(path.join(__dirname, 'product.html'));
});

app.get('/admin', authenticate, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/public/admin.html', (req, res) => {
    res.redirect('/login');
});

// API Routes
app.get('/csrf-token', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.json({ csrfToken: req.cookies.csrfToken });
});

app.get('/user', async (req, res) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) return res.json({ email: 'Guest', isAdmin: false });
        
        const [results] = await queryWithRetry('SELECT email, is_admin FROM users WHERE auth_token = ?', [authToken]);
        if (!results.length) return res.json({ email: 'Guest', isAdmin: false });
        
        res.json({ email: results[0].email, isAdmin: results[0].is_admin });
    } catch (err) {
        logger.error('User fetch error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/categories', async (req, res) => {
    try {
        const [results] = await queryWithRetry('SELECT * FROM categories');
        res.json(results.map(row => ({ catid: row.catid, name: escapeHtml(row.name) })));
    } catch (err) {
        logger.error('Categories error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/products', async (req, res) => {
    try {
        const [results] = await queryWithRetry('SELECT * FROM products');
        res.json(results.map(row => ({
            pid: row.pid,
            catid: row.catid,
            name: escapeHtml(row.name),
            price: row.price,
            description: escapeHtml(row.description),
            image: row.image,
            thumbnail: row.thumbnail
        })));
    } catch (err) {
        logger.error('Products error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/products/:catid', async (req, res) => {
    try {
        const [results] = await queryWithRetry('SELECT * FROM products WHERE catid = ?', [req.params.catid]);
        res.json(results.map(row => ({
            pid: row.pid,
            catid: row.catid,
            name: escapeHtml(row.name),
            price: row.price,
            description: escapeHtml(row.description),
            image: row.image,
            thumbnail: row.thumbnail
        })));
    } catch (err) {
        logger.error('Products by catid error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/product/:pid', async (req, res) => {
    try {
        const [results] = await queryWithRetry('SELECT * FROM products WHERE pid = ?', [req.params.pid]);
        const product = results[0] || {};
        res.json({
            pid: product.pid,
            name: escapeHtml(product.name || ''),
            price: product.price || 0,
            description: escapeHtml(product.description || ''),
            image: product.image || ''
        });
    } catch (err) {
        logger.error('Product error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/orders', authenticate, (req, res) => {
    if (!req.user) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'orders.html'));
});

app.get('/orders-data', authenticate, async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    try {
        const [orders] = await queryWithRetry(
            'SELECT * FROM orders WHERE user_email = ? ORDER BY created_at DESC LIMIT 5',
            [req.user.email]
        );
        res.json(orders.map(order => ({
            order_id: order.orderID,
            email: order.user_email,
            total_amount: order.total_price,
            items: order.items,
            status: order.status,
            created_at: order.created_at
        })));
    } catch (err) {
        logger.error('Error fetching orders:', err);
        res.status(500).json({ error: 'Error fetching orders' });
    }
});

app.get('/admin-orders', authenticate, isAdmin, async (req, res) => {
    try {
        const [orders] = await queryWithRetry('SELECT * FROM orders ORDER BY created_at DESC');
        res.json(orders.map(order => ({
            order_id: order.orderID,
            email: order.user_email,
            total_amount: order.total_price,
            items: order.items,
            status: order.status,
            created_at: order.created_at
        })));
    } catch (err) {
        logger.error('Error fetching admin orders:', err);
        res.status(500).json({ error: 'Error fetching orders' });
    }
});

app.post('/login', validateCsrfToken, async (req, res) => {
    let connection;
    try {
        connection = await db.getConnection();
        const { email, password } = req.body;
        
        const [users] = await connection.query(
            'SELECT userid, email, password, is_admin FROM users WHERE email = ?', 
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = users[0];
        const match = await bcrypt.compare(password, user.password);
        
        if (!match) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const authToken = crypto.randomBytes(32).toString('hex');
        
        await connection.query(
            'UPDATE users SET auth_token = ? WHERE userid = ?',
            [authToken, user.userid]
        );

        res.cookie('authToken', authToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 2 * 24 * 60 * 60 * 1000,
            path: '/'
        });

        res.json({ 
            role: user.is_admin ? 'admin' : 'user',
            redirect: user.is_admin ? '/admin' : '/',
            email: user.email
        });
    } catch (err) {
        logger.error('Login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/logout', validateCsrfToken, authenticate, async (req, res) => {
    try {
        await queryWithRetry('UPDATE users SET auth_token = NULL WHERE userid = ?', [req.user.userid]);
        res.clearCookie('authToken');
        
        const newCsrfToken = generateCsrfToken();
        res.cookie('csrfToken', newCsrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict' 
        });
        
        res.json({ 
            success: true, 
            redirect: '/login',
            csrfToken: newCsrfToken
        });
    } catch (err) {
        logger.error('Logout error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/change-password', validateCsrfToken, authenticate, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword || newPassword.length < 8) {
            return res.status(400).send('Invalid input: New password must be at least 8 characters');
        }

        const match = await bcrypt.compare(currentPassword, req.user.password);
        if (!match) return res.status(401).send('Current password incorrect');
        
        const hash = await bcrypt.hash(newPassword, 10);
        await queryWithRetry('UPDATE users SET password = ?, auth_token = NULL WHERE userid = ?', [hash, req.user.userid]);
        
        res.clearCookie('authToken');
        res.clearCookie('csrfToken');
        res.redirect('/login');
    } catch (err) {
        logger.error('Password change error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/validate-order', validateCsrfToken, authenticate, async (req, res) => {
    let connection;
    try {
        const { items } = req.body;
        if (!items || !Array.isArray(items)) {
            return res.status(400).json({ error: 'Invalid items' });
        }

        connection = await db.getConnection();
        let totalPrice = 0;
        const orderItems = [];
        const currency = 'USD';
        const merchantEmail = 'sb-7vfg240731629@business.example.com';
        const salt = crypto.randomBytes(16).toString('hex');

        for (const item of items) {
            if (!item.pid || !Number.isInteger(item.quantity) || item.quantity <= 0) {
                throw new Error('Invalid item data');
            }

            const [products] = await connection.query('SELECT pid, price FROM products WHERE pid = ?', [item.pid]);
            if (products.length === 0) {
                throw new Error(`Product ${item.pid} not found`);
            }

            const product = products[0];
            totalPrice += product.price * item.quantity;
            orderItems.push({
                pid: item.pid,
                quantity: item.quantity,
                price: product.price
            });
        }

        const dataToHash = [
            currency,
            merchantEmail,
            salt,
            ...orderItems.map(item => `${item.pid}:${item.quantity}:${item.price}`)
        ].join('|');
        const digest = crypto.createHash('sha256').update(dataToHash).digest('hex');

        const userEmail = req.user ? req.user.email : null;
        const [result] = await connection.query(
            'INSERT INTO orders (user_email, items, total_price, digest, salt, status) VALUES (?, ?, ?, ?, ?, ?)',
            [userEmail, JSON.stringify(orderItems), totalPrice, digest, salt, 'pending']
        );

        res.json({ orderID: result.insertId, digest });
    } catch (err) {
        logger.error('Order validation error:', err);
        res.status(400).json({ error: err.message });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/paypal-webhook', (req, res) => {
    webhookQueue.push(async () => {
        try {
            logger.info('Processing PayPal webhook');
            res.setHeader('Content-Type', 'text/plain');

            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);
            const verificationUrl = 'https://www.sandbox.paypal.com/cgi-bin/webscr?cmd=_notify-validate';
            const verificationBody = `cmd=_notify-validate&${new URLSearchParams(req.body).toString()}`;
            const verificationResponse = await fetch(verificationUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: verificationBody,
                signal: controller.signal
            });
            clearTimeout(timeout);
            const verificationResult = await verificationResponse.text();

            if (verificationResult !== 'VERIFIED') {
                logger.error('PayPal verification failed:', verificationResult);
                return res.status(400).send('Invalid PayPal notification');
            }

            const paypalTxnId = req.body.txn_id;
            const [existing] = await queryWithRetry('SELECT transaction_id FROM transactions WHERE paypal_txn_id = ?', [paypalTxnId]);
            if (existing.length > 0) {
                logger.warn('Transaction already processed:', paypalTxnId);
                return res.status(200).send('OK');
            }

            const orderID = parseInt(req.body.invoice);
            const [orders] = await queryWithRetry('SELECT * FROM orders WHERE orderID = ?', [orderID]);
            if (orders.length === 0) {
                logger.error('Order not found:', orderID);
                return res.status(400).send('Order not found');
            }

            const order = orders[0];
            const orderItems = typeof order.items === 'string' ? JSON.parse(order.items) : order.items;

            const currency = 'USD';
            const merchantEmail = 'sb-7vfg240731629@business.example.com';
            const salt = order.salt;
            const dataToHash = [
                currency,
                merchantEmail,
                salt,
                ...orderItems.map(item => `${item.pid}:${item.quantity}:${item.price}`)
            ].join('|');
            const regeneratedDigest = crypto.createHash('sha256').update(dataToHash).digest('hex');

            if (regeneratedDigest !== order.digest) {
                logger.error('Digest mismatch:', regeneratedDigest, order.digest);
                return res.status(400).send('Digest validation failed');
            }

            await queryWithRetry(
                'INSERT INTO transactions (orderID, paypal_txn_id, payment_status, payment_amount, currency_code, payer_email, created_at, items) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    orderID,
                    paypalTxnId,
                    req.body.payment_status,
                    parseFloat(req.body.mc_gross),
                    req.body.mc_currency,
                    req.body.payer_email,
                    new Date(),
                    JSON.stringify(orderItems)
                ]
            );

            const status = req.body.payment_status === 'Completed' ? 'completed' : 'failed';
            await queryWithRetry('UPDATE orders SET status = ? WHERE orderID = ?', [status, orderID]);

            res.status(200).send('OK');
        } catch (err) {
            logger.error('Webhook error:', err);
            res.status(500).send('Internal Server Error');
        }
    });
});

app.post('/add-product', validateCsrfToken, authenticate, isAdmin, upload.single('image'), async (req, res) => {
    const { catid, name, price, description } = req.body;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    const nameError = validateTextInput(name, 255, 'Product name');
    const descError = validateTextInput(description, 1000, 'Description');
    const priceError = validatePrice(price);
    if (nameError || descError || priceError || !catid) {
        if (req.file) await fs.unlink(req.file.path).catch(err => logger.error('File cleanup error:', err));
        return res.status(400).send(nameError || descError || priceError || 'Category ID is required');
    }

    const sanitizedName = sanitizeHtml(name);
    const sanitizedDesc = sanitizeHtml(description);

    try {
        if (imagePath) {
            if (!['image/jpeg', 'image/png', 'image/gif'].includes(req.file.mimetype)) {
                await fs.unlink(req.file.path).catch(err => logger.error('File cleanup error:', err));
                return res.status(400).send('Invalid image type. Only JPEG, PNG, or GIF allowed.');
            }

            await sharp(req.file.path)
                .resize(200, 200)
                .toFile(`uploads/thumbnail-${req.file.filename}`);
            const thumbnailPath = `/uploads/thumbnail-${req.file.filename}`;
            await queryWithRetry(
                'INSERT INTO products (catid, name, price, description, image, thumbnail) VALUES (?, ?, ?, ?, ?, ?)',
                [catid, sanitizedName, price, sanitizedDesc, imagePath, thumbnailPath]
            );
        } else {
            await queryWithRetry(
                'INSERT INTO products (catid, name, price, description) VALUES (?, ?, ?, ?)',
                [catid, sanitizedName, price, sanitizedDesc]
            );
        }
        res.send('Product added');
    } catch (err) {
        logger.error('Add product error:', err);
        if (req.file) await fs.unlink(req.file.path).catch(err => logger.error('File cleanup error:', err));
        res.status(500).send('Internal Server Error');
    }
});

app.put('/update-product/:pid', validateCsrfToken, authenticate, isAdmin, upload.single('image'), async (req, res) => {
    const { catid, name, price, description } = req.body;
    const pid = req.params.pid;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    const nameError = validateTextInput(name, 255, 'Product name');
    const descError = validateTextInput(description, 1000, 'Description');
    const priceError = validatePrice(price);
    if (nameError || descError || priceError || !catid) {
        if (req.file) await fs.unlink(req.file.path).catch(err => logger.error('File cleanup error:', err));
        return res.status(400).send(nameError || descError || priceError || 'Category ID is required');
    }

    const sanitizedName = sanitizeHtml(name);
    const sanitizedDesc = sanitizeHtml(description);

    try {
        if (imagePath) {
            if (!['image/jpeg', 'image/png', 'image/gif'].includes(req.file.mimetype)) {
                await fs.unlink(req.file.path).catch(err => logger.error('File cleanup error:', err));
                return res.status(400).send('Invalid image type. Only JPEG, PNG, or GIF allowed.');
            }

            await sharp(req.file.path)
                .resize(200, 200)
                .toFile(`uploads/thumbnail-${req.file.filename}`);
            const thumbnailPath = `/uploads/thumbnail-${req.file.filename}`;
            await queryWithRetry(
                'UPDATE products SET catid=?, name=?, price=?, description=?, image=?, thumbnail=? WHERE pid=?',
                [catid, sanitizedName, price, sanitizedDesc, imagePath, thumbnailPath, pid]
            );
        } else {
            await queryWithRetry(
                'UPDATE products SET catid=?, name=?, price=?, description=? WHERE pid=?',
                [catid, sanitizedName, price, sanitizedDesc, pid]
            );
        }
        res.send('Product updated');
    } catch (err) {
        logger.error('Update product error:', err);
        if (req.file) await fs.unlink(req.file.path).catch(err => logger.error('File cleanup error:', err));
        res.status(500).send('Internal Server Error');
    }
});

app.post('/add-category', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    const { name } = req.body;
    const nameError = validateTextInput(name, 255, 'Category name');
    if (nameError) return res.status(400).send(nameError);

    const sanitizedName = sanitizeHtml(name);
    try {
        await queryWithRetry('INSERT INTO categories (name) VALUES (?)', [sanitizedName]);
        res.send('Category added');
    } catch (err) {
        logger.error('Add category error:', err);
        return res.status(500).send('Internal Server Error');
    }
});

app.post('/send-message', validateCsrfToken, authenticate, async (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    
    const { content } = req.body;
    const contentError = validateTextInput(content, 1000, 'Message content');
    if (contentError) return res.status(400).json({ error: contentError });

    const sanitizedContent = sanitizeHtml(content);
    try {
        await queryWithRetry('INSERT INTO messages (user_email, content) VALUES (?, ?)', [req.user.email, sanitizedContent]);
        res.json({ success: true });
    } catch (err) {
        logger.error('Send message error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/messages', authenticate, async (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    
    try {
        const [messages] = await queryWithRetry(
            'SELECT message_id, user_email, content, created_at, admin_reply, replied_at FROM messages WHERE user_email = ? ORDER BY created_at ASC',
            [req.user.email]
        );
        res.json(messages.map(msg => ({
            message_id: msg.message_id,
            user_email: msg.user_email,
            content: escapeHtml(msg.content),
            created_at: msg.created_at,
            admin_reply: msg.admin_reply ? escapeHtml(msg.admin_reply) : null,
            replied_at: msg.replied_at
        })));
    } catch (err) {
        logger.error('Fetch messages error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/admin-messages', authenticate, isAdmin, async (req, res) => {
    try {
        const [messages] = await queryWithRetry('SELECT * FROM messages ORDER BY created_at DESC');
        res.json(messages.map(msg => ({
            message_id: msg.message_id,
            user_email: msg.user_email,
            content: escapeHtml(msg.content),
            created_at: msg.created_at,
            admin_reply: msg.admin_reply ? escapeHtml(msg.admin_reply) : null,
            replied_at: msg.replied_at
        })));
    } catch (err) {
        logger.error('Fetch admin messages error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/reply-message', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    const { message_id, reply } = req.body;
    const replyError = validateTextInput(reply, 1000, 'Reply content');
    if (replyError || !message_id) {
        logger.error('Reply validation error:', { message_id, replyError });
        return res.status(400).json({ error: replyError || 'Message ID is required' });
    }

    const sanitizedReply = sanitizeHtml(reply);
    try {
        const [result] = await queryWithRetry(
            'UPDATE messages SET admin_reply = ?, replied_at = NOW() WHERE message_id = ?',
            [sanitizedReply, message_id]
        );
        if (result.affectedRows === 0) {
            logger.error('Message not found:', message_id);
            return res.status(404).json({ error: 'Message not found' });
        }
        res.json({ success: true });
    } catch (err) {
        logger.error('Reply message error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.put('/update-category/:catid', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    const { name } = req.body;
    const catid = req.params.catid;
    const nameError = validateTextInput(name, 255, 'Category name');
    if (nameError) return res.status(400).send(nameError);

    const sanitizedName = sanitizeHtml(name);
    try {
        await queryWithRetry('UPDATE categories SET name=? WHERE catid=?', [sanitizedName, catid]);
        res.send('Category updated');
    } catch (err) {
        logger.error('Update category error:', err);
        return res.status(500).send('Internal Server Error');
    }
});

app.delete('/delete-product/:pid', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    try {
        await queryWithRetry('DELETE FROM products WHERE pid = ?', [req.params.pid]);
        res.send('Product deleted');
    } catch (err) {
        logger.error('Delete product error:', err);
        return res.status(500).send('Internal Server Error');
    }
});

app.delete('/delete-category/:catid', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    try {
        await queryWithRetry('DELETE FROM categories WHERE catid = ?', [req.params.catid]);
        res.send('Category deleted');
    } catch (err) {
        logger.error('Delete category error:', err);
        return res.status(500).send('Internal Server Error');
    }
});

// 全局错误处理
app.use((err, req, res, next) => {
    logger.error('Server error:', err);
    res.status(500).send('Internal Server Error');
});

// 捕获未处理异常，防止进程崩溃
process.on('uncaughtException', (err) => {
    logger.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

http.createServer(app).listen(3443, '0.0.0.0', () => {
    logger.info('HTTP Server running on port 3443');
});