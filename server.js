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
dotenv.config();

const fs = require('fs');

const app = express();
const upload = multer({ dest: 'uploads/', limits: { fileSize: 10 * 1024 * 1024 } });

const db = mysql.createPool({
    host: process.env.DB_HOST || 'ierg421074982.mysql.database.azure.com',
    user: process.env.DB_USER || 'admin123',
    password: process.env.DB_PASSWORD || '@Zhang1325020',
    database: process.env.DB_NAME || 'dummy_shop',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: {
        rejectUnauthorized: true,
        ca: fs.readFileSync("./DigiCertGlobalRootCA.crt.pem", "utf8"),
    }
});

db.getConnection((err, connection) => {
    if (err) {
        console.error('Database connection failed:', err);
        process.exit(1);
    }
    console.log('Database connected successfully');
    connection.release();
});

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
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname, { index: false }));

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
        return res.status(403).send('CSRF token validation failed');
    }
    next();
};

// Authentication Middleware
const authenticate = async (req, res, next) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) return next();
        
        const [results] = await db.query('SELECT * FROM users WHERE auth_token = ?', [authToken]);
        if (!results.length) return next();
        
        req.user = results[0];
        next();
    } catch (err) {
        console.error('Auth error:', err);
        res.status(500).send('Internal Server Error');
    }
};

const isAdmin = (req, res, next) => {
    if (!req.user || !req.user.is_admin) return res.status(403).send('Admin access required');
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
        
        const [results] = await db.query('SELECT email, is_admin FROM users WHERE auth_token = ?', [authToken]);
        if (!results.length) return res.json({ email: 'Guest', isAdmin: false });
        
        res.json({ email: results[0].email, isAdmin: results[0].is_admin });
    } catch (err) {
        console.error('User fetch error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/categories', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM categories');
        res.json(results.map(row => ({ catid: row.catid, name: escapeHtml(row.name) })));
    } catch (err) {
        console.error('Categories error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/products', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM products');
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
        console.error('Products error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/products/:catid', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM products WHERE catid = ?', [req.params.catid]);
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
        console.error('Products by catid error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/product/:pid', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM products WHERE pid = ?', [req.params.pid]);
        const product = results[0] || {};
        res.json({
            pid: product.pid,
            name: escapeHtml(product.name || ''),
            price: product.price || 0,
            description: escapeHtml(product.description || ''),
            image: product.image || ''
        });
    } catch (err) {
        console.error('Product error:', err);
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
        const [orders] = await db.query(
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
        console.error('Error fetching orders:', err);
        res.status(500).json({ error: 'Error fetching orders' });
    }
});

app.get('/admin-orders', authenticate, isAdmin, async (req, res) => {
    try {
        const [orders] = await db.query('SELECT * FROM orders ORDER BY created_at DESC');
        res.json(orders.map(order => ({
            order_id: order.orderID,
            email: order.user_email,
            total_amount: order.total_price,
            items: order.items,
            status: order.status,
            created_at: order.created_at
        })));
    } catch (err) {
        console.error('Error fetching admin orders:', err);
        res.status(500).json({ error: 'Error fetching orders' });
    }
});

app.post('/login', validateCsrfToken, async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const connection = await db.getConnection();
        
        try {
            const [users] = await connection.query(
                'SELECT userid, email, password, is_admin FROM users WHERE email = ?', 
                [email]
            );

            if (users.length === 0) {
                connection.release();
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const user = users[0];
            const match = await bcrypt.compare(password, user.password);
            
            if (!match) {
                connection.release();
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const authToken = crypto.randomBytes(32).toString('hex');
            
            await connection.query(
                'UPDATE users SET auth_token = ? WHERE userid = ?',
                [authToken, user.userid]
            );

            connection.release();

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
            connection.release();
            console.error('Login error:', err.stack);
            res.status(500).json({ 
                error: 'Internal server error',
                details: process.env.NODE_ENV === 'development' ? err.message : null
            });
        }
    } catch (err) {
        console.error('Connection error:', err.stack);
        res.status(500).json({ 
            error: 'Internal server error',
            details: process.env.NODE_ENV === 'development' ? err.message : null
        });
    }
});

app.post('/logout', validateCsrfToken, authenticate, async (req, res) => {
    try {
        await db.query('UPDATE users SET auth_token = NULL WHERE userid = ?', [req.user.userid]);
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
        console.error('Logout error:', err);
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
        await db.query('UPDATE users SET password = ?, auth_token = NULL WHERE userid = ?', [hash, req.user.userid]);
        
        res.clearCookie('authToken');
        res.clearCookie('csrfToken');
        res.redirect('/login');
    } catch (err) {
        console.error('Password change error:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/validate-order', validateCsrfToken, authenticate, async (req, res) => {
    try {
        console.log('Validate-order request body:', req.body);
        const { items } = req.body;
        if (!items || !Array.isArray(items)) {
            console.log('Invalid items detected');
            return res.status(400).json({ error: 'Invalid items' });
        }

        const connection = await db.getConnection();
        try {
            let totalPrice = 0;
            const orderItems = [];
            const currency = 'USD';
            const merchantEmail = 'sb-7vfg240731629@business.example.com';
            const salt = crypto.randomBytes(16).toString('hex');

            for (const item of items) {
                console.log('Processing item:', item);
                if (!item.pid || !Number.isInteger(item.quantity) || item.quantity <= 0) {
                    console.log('Invalid item data:', item);
                    throw new Error('Invalid item data');
                }

                const [products] = await connection.query('SELECT pid, price FROM products WHERE pid = ?', [item.pid]);
                console.log('Database query result for pid', item.pid, ':', products);
                if (products.length === 0) {
                    console.log('Product not found:', item.pid);
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
            console.log('Digest data:', dataToHash);
            console.log('Generated digest:', digest);

            const userEmail = req.user ? req.user.email : null;
            console.log('User email:', userEmail);
            const [result] = await connection.query(
                'INSERT INTO orders (user_email, items, total_price, digest, salt, status) VALUES (?, ?, ?, ?, ?, ?)',
                [userEmail, JSON.stringify(orderItems), totalPrice, digest, salt, 'pending']
            );
            console.log('Order inserted, ID:', result.insertId);

            connection.release();
            res.setHeader('Content-Type', 'application/json');
            res.json({ orderID: result.insertId, digest });
        } catch (err) {
            connection.release();
            console.error('Order validation error:', err);
            res.setHeader('Content-Type', 'application/json');
            res.status(400).json({ error: err.message });
        }
    } catch (err) {
        console.error('Connection error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/paypal-webhook', async (req, res) => {
    try {
        console.log('PayPal webhook received:', req.body);
        res.setHeader('Content-Type', 'text/plain');

        // Verify PayPal IPN
        const verificationUrl = 'https://www.sandbox.paypal.com/cgi-bin/webscr?cmd=_notify-validate';
        const verificationBody = `cmd=_notify-validate&${new URLSearchParams(req.body).toString()}`;
        const verificationResponse = await fetch(verificationUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: verificationBody
        });
        const verificationResult = await verificationResponse.text();

        if (verificationResult !== 'VERIFIED') {
            console.error('PayPal verification failed:', verificationResult);
            return res.status(400).send('Invalid PayPal notification');
        }

        // Check if transaction already processed
        const paypalTxnId = req.body.txn_id;
        const [existing] = await db.query('SELECT transaction_id FROM transactions WHERE paypal_txn_id = ?', [paypalTxnId]);
        if (existing.length > 0) {
            console.warn('Transaction already processed:', paypalTxnId);
            return res.status(200).send('OK');
        }

        // Fetch order
        const orderID = parseInt(req.body.invoice);
        const [orders] = await db.query('SELECT * FROM orders WHERE orderID = ?', [orderID]);
        if (orders.length === 0) {
            console.error('Order not found:', orderID);
            return res.status(400).send('Order not found');
        }

        const order = orders[0];
        // Check if order.items is already an object; if not, parse it
        const orderItems = typeof order.items === 'string' ? JSON.parse(order.items) : order.items;

        // Regenerate digest
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
            console.error('Digest mismatch:', regeneratedDigest, order.digest);
            return res.status(400).send('Digest validation failed');
        }

        // Save transaction with product list
        await db.query(
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

        // Update order status
        const status = req.body.payment_status === 'Completed' ? 'completed' : 'failed';
        await db.query('UPDATE orders SET status = ? WHERE orderID = ?', [status, orderID]);

        res.status(200).send('OK');
    } catch (err) {
        console.error('Webhook error:', err);
        res.setHeader('Content-Type', 'text/plain');
        res.status(500).send('Internal Server Error');
    }
});

app.post('/add-product', validateCsrfToken, authenticate, isAdmin, upload.single('image'), async (req, res) => {
    const { catid, name, price, description } = req.body;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    const nameError = validateTextInput(name, 255, 'Product name');
    const descError = validateTextInput(description, 1000, 'Description');
    const priceError = validatePrice(price);
    if (nameError || descError || priceError || !catid) {
        return res.status(400).send(nameError || descError || priceError || 'Category ID is required');
    }

    const sanitizedName = sanitizeHtml(name);
    const sanitizedDesc = sanitizeHtml(description);

    if (imagePath) {
        if (!['image/jpeg', 'image/png', 'image/gif'].includes(req.file.mimetype)) {
            return res.status(400).send('Invalid image type. Only JPEG, PNG, or GIF allowed.');
        }

        sharp(req.file.path)
            .resize(200, 200)
            .toFile(`uploads/thumbnail-${req.file.filename}`, (err) => {
                if (err) {
                    console.error('Image resize error:', err);
                    return res.status(500).send('Internal Server Error');
                }
                const thumbnailPath = `/uploads/thumbnail-${req.file.filename}`;
                const sql = 'INSERT INTO products (catid, name, price, description, image, thumbnail) VALUES (?, ?, ?, ?, ?, ?)';
                db.query(sql, [catid, sanitizedName, price, sanitizedDesc, imagePath, thumbnailPath], (err) => {
                    if (err) {
                        console.error('Add product error:', err);
                        return res.status(500).send('Internal Server Error');
                    }
                    res.send('Product added');
                });
            });
    } else {
        const sql = 'INSERT INTO products (catid, name, price, description) VALUES (?, ?, ?, ?)';
        db.query(sql, [catid, sanitizedName, price, sanitizedDesc], (err) => {
            if (err) {
                console.error('Add product error:', err);
                return res.status(500).send('Internal Server Error');
            }
            res.send('Product added');
        });
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
        return res.status(400).send(nameError || descError || priceError || 'Category ID is required');
    }

    const sanitizedName = sanitizeHtml(name);
    const sanitizedDesc = sanitizeHtml(description);

    if (imagePath) {
        if (!['image/jpeg', 'image/png', 'image/gif'].includes(req.file.mimetype)) {
            return res.status(400).send('Invalid image type. Only JPEG, PNG, or GIF allowed.');
        }

        sharp(req.file.path)
            .resize(200, 200)
            .toFile(`uploads/thumbnail-${req.file.filename}`, (err) => {
                if (err) {
                    console.error('Image resize error:', err);
                    return res.status(500).send('Internal Server Error');
                }
                const thumbnailPath = `/uploads/thumbnail-${req.file.filename}`;
                const sql = 'UPDATE products SET catid=?, name=?, price=?, description=?, image=?, thumbnail=? WHERE pid=?';
                db.query(sql, [catid, sanitizedName, price, sanitizedDesc, imagePath, thumbnailPath, pid], (err) => {
                    if (err) {
                        console.error('Update product error:', err);
                        return res.status(500).send('Internal Server Error');
                    }
                    res.send('Product updated');
                });
            });
    } else {
        const sql = 'UPDATE products SET catid=?, name=?, price=?, description=? WHERE pid=?';
        db.query(sql, [catid, sanitizedName, price, sanitizedDesc, pid], (err) => {
            if (err) {
                console.error('Update product error:', err);
                return res.status(500).send('Internal Server Error');
            }
            res.send('Product updated');
        });
    }
});

app.post('/add-category', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    const { name } = req.body;
    const nameError = validateTextInput(name, 255, 'Category name');
    if (nameError) return res.status(400).send(nameError);

    const sanitizedName = sanitizeHtml(name);
    db.query('INSERT INTO categories (name) VALUES (?)', [sanitizedName], (err) => {
        if (err) {
            console.error('Add category error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.send('Category added');
    });
});

// 发送消息
app.post('/send-message', validateCsrfToken, authenticate, async (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    
    const { content } = req.body;
    const contentError = validateTextInput(content, 1000, 'Message content');
    if (contentError) return res.status(400).json({ error: contentError });

    const sanitizedContent = sanitizeHtml(content);
    try {
        await db.query('INSERT INTO messages (user_email, content) VALUES (?, ?)', [req.user.email, sanitizedContent]);
        res.json({ success: true });
    } catch (err) {
        console.error('Send message error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 获取用户消息
app.get('/messages', authenticate, async (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    
    try {
        const [messages] = await db.query(
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
        console.error('Fetch messages error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 获取管理员消息（所有用户的消息）
app.get('/admin-messages', authenticate, isAdmin, async (req, res) => {
    try {
        const [messages] = await db.query('SELECT * FROM messages ORDER BY created_at DESC');
        res.json(messages.map(msg => ({
            message_id: msg.message_id,
            user_email: msg.user_email,
            content: escapeHtml(msg.content),
            created_at: msg.created_at,
            admin_reply: msg.admin_reply ? escapeHtml(msg.admin_reply) : null,
            replied_at: msg.replied_at
        })));
    } catch (err) {
        console.error('Fetch admin messages error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 管理员回复消息
app.post('/reply-message', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    const { message_id, reply } = req.body;
    const replyError = validateTextInput(reply, 1000, 'Reply content');
    if (replyError || !message_id) {
        console.error('Reply validation error:', { message_id, replyError });
        return res.status(400).json({ error: replyError || 'Message ID is required' });
    }

    const sanitizedReply = sanitizeHtml(reply);
    try {
        const [result] = await db.query(
            'UPDATE messages SET admin_reply = ?, replied_at = NOW() WHERE message_id = ?',
            [sanitizedReply, message_id]
        );
        if (result.affectedRows === 0) {
            console.error('Message not found:', message_id);
            return res.status(404).json({ error: 'Message not found' });
        }
        console.log('Reply sent:', { message_id, reply: sanitizedReply });
        res.json({ success: true });
    } catch (err) {
        console.error('Reply message error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.put('/update-category/:catid', validateCsrfToken, authenticate, isAdmin, async (req, res) => {
    const { name } = req.body;
    const catid = req.params.catid;
    const nameError = validateTextInput(name, 255, 'Category name');
    if (nameError) return res.status(400).send(nameError);

    const sanitizedName = sanitizeHtml(name);
    db.query('UPDATE categories SET name=? WHERE catid=?', [sanitizedName, catid], (err) => {
        if (err) {
            console.error('Update category error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.send('Category updated');
    });
});

app.delete('/delete-product/:pid', validateCsrfToken, authenticate, isAdmin, (req, res) => {
    db.query('DELETE FROM products WHERE pid = ?', [req.params.pid], (err) => {
        if (err) {
            console.error('Delete product error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.send('Product deleted');
    });
});

app.delete('/delete-category/:catid', validateCsrfToken, authenticate, isAdmin, (req, res) => {
    db.query('DELETE FROM categories WHERE catid = ?', [req.params.catid], (err) => {
        if (err) {
            console.error('Delete category error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.send('Category deleted');
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);
    res.status(500).send('Internal Server Error');
});

http.createServer(app).listen(3443, '0.0.0.0', () => {
    console.log('HTTP Server running on port 3443');
});