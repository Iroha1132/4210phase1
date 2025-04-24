const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql");
const app = express();
const path = require("path");
const multer = require("multer");
const sharp = require("sharp");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const xss = require("xss");
const csrf = require("csurf");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const https = require("https");
const fs = require("fs");
const crypto = require("crypto");
const axios = require("axios"); // 新增 axios 用于 PayPal REST API

const upload = multer({ dest: "uploads/" });

// PayPal REST API 配置
const PAYPAL_CLIENT_ID = "AV6sDnhRtyl78RIXw-yeIwWM7DqUTYDvlUSP5l82fY9ZyIqubZxnahfJJ0uMPCuUOtLCA0dyLCw_gxPq";
const PAYPAL_CLIENT_SECRET = "EOOXF8GeF25ErUzFKC0Pz6BMVxgBEnFbrLm9aVoTMu0XC3iaoPgYUPddAZhhdgBM0qpyhybRl793e7QJ";
const PAYPAL_API = "https://api-m.sandbox.paypal.com";

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://www.paypal.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: [
        "'self'",
        "data:",
        "https://ierg4210.eastasia.cloudapp.azure.com",
      ],
      connectSrc: ["'self'", "https://api-m.sandbox.paypal.com"],
      frameSrc: ["'self'", "https://www.paypal.com"],
      objectSrc: ["'none'"],
    },
  })
);

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(cookieParser());
const csrfProtection = csrf({
  cookie: {
    key: "_csrf",
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 86400,
  },
});

app.use(csrfProtection);
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.paypal.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api-m.sandbox.paypal.com; frame-src 'self' https://www.paypal.com;"
  );
  next();
});

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "zhang1325020",
  database: "dummy_shop",
});

db.connect((err) => {
  if (err) throw err;
  console.log("MySQL connected");

  // 创建 orders 表
  const createOrdersTable = `
    CREATE TABLE IF NOT EXISTS orders (
      orderId INT AUTO_INCREMENT PRIMARY KEY,
      userId INT NULL,
      username VARCHAR(255) NULL,
      currency VARCHAR(3) DEFAULT 'HKD',
      totalPrice DECIMAL(10,2) NOT NULL,
      paypalOrderId VARCHAR(255) NULL,
      status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(userid)
    )`;
  db.query(createOrdersTable, (err) => {
    if (err) throw err;
  });

  // 创建 order_items 表
  const createOrderItemsTable = `
    CREATE TABLE IF NOT EXISTS order_items (
      itemId INT AUTO_INCREMENT PRIMARY KEY,
      orderId INT NOT NULL,
      pid INT NOT NULL,
      quantity INT NOT NULL,
      price DECIMAL(10,2) NOT NULL,
      FOREIGN KEY (orderId) REFERENCES orders(orderId),
      FOREIGN KEY (pid) REFERENCES products(pid)
    )`;
  db.query(createOrderItemsTable, (err) => {
    if (err) throw err;
  });
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// 获取 PayPal 访问令牌
async function getPayPalAccessToken() {
  const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString('base64');
  const response = await axios.post(`${PAYPAL_API}/v1/oauth2/token`, 'grant_type=client_credentials', {
    headers: {
      'Authorization': `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });
  return response.data.access_token;
}

const authenticateAdmin = (req, res, next) => {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ authenticated: false });

  jwt.verify(token, "secret_key", (err, decoded) => {
    if (err) return res.status(401).json({ authenticated: false });

    const sql = "SELECT admin_flag FROM users WHERE userid = ?";
    db.query(sql, [decoded.userId], (err, results) => {
      if (err || !results.length || !results[0].admin_flag) {
        return res.status(403).json({ error: "Admin access required" });
      }
      req.userId = decoded.userId;
      next();
    });
  });
};

app.get("/check-auth", (req, res) => {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ authenticated: false });

  jwt.verify(token, "secret_key", (err, decoded) => {
    if (err) return res.status(401).json({ authenticated: false });

    const sql = "SELECT userid FROM users WHERE userid = ?";
    db.query(sql, [decoded.userId], (err, results) => {
      if (err || !results.length) {
        return res.status(401).json({ authenticated: false });
      }
      res.json({ authenticated: true });
    });
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM users WHERE email = ?";
  
  db.query(sql, [xss(email)], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "服务器错误" });
    }

    if (results.length > 0) {
      const user = results[0];
      if (bcrypt.compareSync(password, user.password)) {
        const sessionId = crypto.randomBytes(16).toString('hex');
        const token = jwt.sign({ 
          userId: user.userid,
          sessionId: sessionId,
          loginSeq: crypto.randomBytes(8).toString('hex')
        }, "secret_key", { expiresIn: "2d" });

        res.cookie("auth_token", token, {
          httpOnly: true,
          secure: true,
          maxAge: 172800000,
          sameSite: "strict"
        });

        return res.json({
          success: true,
          isAdmin: user.admin_flag === 1,
          redirect: user.admin_flag === 1 ? "/admin.html" : "/user-dashboard.html"
        });
      }
    }
    
    res.status(401).json({ 
      success: false, 
      message: "邮箱或密码错误" 
    });
  });
});

app.post("/logout", (req, res) => {
  res.clearCookie("auth_token");
  res.json({ success: true });
});

app.post("/change-password", csrfProtection, (req, res) => {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ authenticated: false });

  jwt.verify(token, "secret_key", (err, decoded) => {
    if (err) return res.status(401).json({ authenticated: false });

    const { currentPassword, newPassword } = req.body;
    const userId = decoded.userId;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: "New password must be at least 8 characters" });
    }

    const sql = "SELECT password FROM users WHERE userid = ?";
    db.query(sql, [userId], (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ success: false, message: "Server error" });
      }

      if (results.length === 0) {
        return res.status(404).json({ success: false, message: "User not found" });
      }

      const user = results[0];

      if (!bcrypt.compareSync(currentPassword, user.password)) {
        return res.status(401).json({ success: false, message: "Current password is incorrect" });
      }

      const hashedPassword = bcrypt.hashSync(newPassword, 10);

      const updateSql = "UPDATE users SET password = ? WHERE userid = ?";
      db.query(updateSql, [hashedPassword, userId], (err, result) => {
        if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ success: false, message: "Failed to update password" });
        }

        res.clearCookie("auth_token");
        res.json({ success: true, message: "Password changed successfully" });
      });
    });
  });
});

app.get("/categories", (req, res) => {
  const sql = "SELECT * FROM categories";
  db.query(sql, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.get("/category/:catid", (req, res) => {
  const catid = xss(req.params.catid);
  const sql = "SELECT * FROM categories WHERE catid = ?";
  db.query(sql, [catid], (err, results) => {
    if (err) throw err;
    res.json(results[0]);
  });
});

app.get("/products", (req, res) => {
  const sql = "SELECT * FROM products";
  db.query(sql, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.get("/product/:pid", (req, res) => {
  const pid = xss(req.params.pid);
  const sql = "SELECT * FROM products WHERE pid = ?";
  db.query(sql, [pid], (err, results) => {
    if (err) throw err;
    res.json(results[0]);
  });
});

app.get("/products/:catid", (req, res) => {
  const catid = xss(req.params.catid);
  const sql = "SELECT * FROM products WHERE catid = ?";
  db.query(sql, [catid], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.get("/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.get("/user-info", (req, res) => {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ authenticated: false });

  jwt.verify(token, "secret_key", (err, decoded) => {
    if (err) return res.status(401).json({ authenticated: false });

    const sql = "SELECT email, admin_flag FROM users WHERE userid = ?";
    db.query(sql, [decoded.userId], (err, results) => {
      if (err || !results.length) {
        return res.status(404).json({ error: "User not found" });
      }
      res.json({
        email: results[0].email,
        isAdmin: results[0].admin_flag === 1,
      });
    });
  });
});

app.get("/check-admin", authenticateAdmin, (req, res) => {
  const sql = "SELECT admin_flag FROM users WHERE userid = ?";
  db.query(sql, [req.userId], (err, results) => {
    if (err || !results.length) {
      return res.status(403).json({ isAdmin: false });
    }
    res.json({ isAdmin: results[0].admin_flag === 1 });
  });
});

app.post(
  "/add-product",
  upload.single("image"),
  authenticateAdmin,
  (req, res) => {
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
          const sql =
            "INSERT INTO products (catid, name, price, description, image, thumbnail) VALUES (?, ?, ?, ?, ?, ?)";
          db.query(
            sql,
            [
              xss(catid),
              sanitizedName,
              xss(price),
              sanitizedDescription,
              imagePath,
              thumbnailPath,
            ],
            (err, result) => {
              if (err) throw err;
              res.send("Product added");
            }
          );
        });
    } else {
      const sql =
        "INSERT INTO products (catid, name, price, description) VALUES (?, ?, ?, ?)";
      db.query(
        sql,
        [xss(catid), sanitizedName, xss(price), sanitizedDescription],
        (err, result) => {
          if (err) throw err;
          res.send("Product added");
        }
      );
    }
  }
);

app.put(
  "/update-product/:pid",
  upload.single("image"),
  authenticateAdmin,
  (req, res) => {
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
          const sql =
            "UPDATE products SET catid = ?, name = ?, price = ?, description = ?, image = ?, thumbnail = ? WHERE pid = ?";
          db.query(
            sql,
            [
              xss(catid),
              sanitizedName,
              xss(price),
              sanitizedDescription,
              imagePath,
              thumbnailPath,
              pid,
            ],
            (err, result) => {
              if (err) throw err;
              res.send("Product updated");
            }
          );
        });
    } else {
      const sql =
        "UPDATE products SET catid = ?, name = ?, price = ?, description = ? WHERE pid = ?";
      db.query(
        sql,
        [xss(catid), sanitizedName, xss(price), sanitizedDescription, pid],
        (err, result) => {
          if (err) throw err;
          res.send("Product updated");
        }
      );
    }
  }
);

app.post("/add-category", authenticateAdmin, (req, res) => {
  const { name } = req.body;
  const sanitizedName = xss(name);
  const sql = "INSERT INTO categories (name) VALUES (?)";
  db.query(sql, [sanitizedName], (err, result) => {
    if (err) throw err;
    res.send("Category added");
  });
});

app.put("/update-category/:catid", authenticateAdmin, (req, res) => {
  const catid = xss(req.params.catid);
  const { name } = req.body;
  const sanitizedName = xss(name);
  const sql = "UPDATE categories SET name = ? WHERE catid = ?";
  db.query(sql, [sanitizedName, catid], (err, result) => {
    if (err) throw err;
    res.send("Category updated");
  });
});

app.delete("/delete-product/:pid", authenticateAdmin, (req, res) => {
  const pid = xss(req.params.pid);
  const sql = "DELETE FROM products WHERE pid = ?";
  db.query(sql, [pid], (err, result) => {
    if (err) throw err;
    res.send("Product deleted");
  });
});

app.delete("/delete-category/:catid", authenticateAdmin, (req, res) => {
  const catid = xss(req.params.catid);
  const sql = "DELETE FROM categories WHERE catid = ?";
  db.query(sql, [catid], (err, result) => {
    if (err) throw err;
    res.send("Category deleted");
  });
});

// 创建 PayPal 订单
app.post("/create-paypal-order", csrfProtection, async (req, res) => {
  const { items } = req.body;
  const token = req.cookies.auth_token;
  let userId = null;
  let username = "guest";

  if (token) {
    try {
      const decoded = jwt.verify(token, "secret_key");
      userId = decoded.userId;
      const sql = "SELECT email FROM users WHERE userid = ?";
      const results = await new Promise((resolve, reject) => {
        db.query(sql, [userId], (err, results) => {
          if (err) reject(err);
          resolve(results);
        });
      });
      if (results.length > 0) {
        username = results[0].email;
      }
    } catch (err) {
      console.error("JWT verification error:", err);
    }
  }

  const pids = items.map((item) => xss(item.pid));
  const quantities = items.map((item) => parseInt(item.quantity));
  if (quantities.some((q) => q <= 0)) {
    return res.status(400).json({ success: false, message: "Invalid quantity" });
  }

  try {
    const sql = "SELECT pid, name, price FROM products WHERE pid IN (?)";
    const results = await new Promise((resolve, reject) => {
      db.query(sql, [pids], (err, results) => {
        if (err) reject(err);
        resolve(results);
      });
    });

    if (results.length !== pids.length) {
      return res.status(400).json({ success: false, message: "Invalid products" });
    }

    const prices = {};
    const productNames = {};
    results.forEach((row) => {
      prices[row.pid] = row.price;
      productNames[row.pid] = row.name;
    });

    let totalPrice = 0;
    items.forEach((item) => {
      totalPrice += prices[item.pid] * item.quantity;
    });

    // 创建本地订单
    const orderSql = "INSERT INTO orders (userId, username, totalPrice, status) VALUES (?, ?, ?, 'pending')";
    const orderResult = await new Promise((resolve, reject) => {
      db.query(orderSql, [userId, username, totalPrice], (err, result) => {
        if (err) reject(err);
        resolve(result);
      });
    });

    const orderId = orderResult.insertId;
    const itemSql = "INSERT INTO order_items (orderId, pid, quantity, price) VALUES ?";
    const itemValues = items.map((item) => [
      orderId,
      item.pid,
      item.quantity,
      prices[item.pid],
    ]);

    await new Promise((resolve, reject) => {
      db.query(itemSql, [itemValues], (err) => {
        if (err) reject(err);
        resolve();
      });
    });

    // 创建 PayPal 订单
    const accessToken = await getPayPalAccessToken();
    const paypalResponse = await axios.post(`${PAYPAL_API}/v2/checkout/orders`, {
      intent: "CAPTURE",
      purchase_units: [{
        amount: {
          currency_code: "HKD",
          value: totalPrice.toFixed(2),
          breakdown: {
            item_total: { currency_code: "HKD", value: totalPrice.toFixed(2) },
          },
        },
        items: items.map((item) => ({
          name: productNames[item.pid],
          quantity: item.quantity,
          unit_amount: { currency_code: "HKD", value: prices[item.pid].toFixed(2) },
        })),
        custom_id: orderId.toString(), // 将本地订单ID传递给 PayPal
      }],
      application_context: {
        return_url: "https://ierg4210.eastasia.cloudapp.azure.com",
        cancel_url: "https://ierg4210.eastasia.cloudapp.azure.com",
      },
    }, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    // 更新订单以存储 PayPal 订单 ID
    const updateSql = "UPDATE orders SET paypalOrderId = ? WHERE orderId = ?";
    await new Promise((resolve, reject) => {
      db.query(updateSql, [paypalResponse.data.id, orderId], (err) => {
        if (err) reject(err);
        resolve();
      });
    });

    res.json({ success: true, id: paypalResponse.data.id });
  } catch (error) {
    console.error("Create order error:", error);
    res.status(500).json({ success: false, message: "Failed to create order" });
  }
});

// 捕获 PayPal 支付
app.post("/capture-paypal-order", csrfProtection, async (req, res) => {
  const { orderID } = req.body;

  try {
    const accessToken = await getPayPalAccessToken();
    const captureResponse = await axios.post(`${PAYPAL_API}/v2/checkout/orders/${orderID}/capture`, {}, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (captureResponse.data.status === "COMPLETED") {
      const localOrderId = captureResponse.data.purchase_units[0].custom_id;
      const updateSql = "UPDATE orders SET status = 'completed' WHERE orderId = ? AND paypalOrderId = ?";
      await new Promise((resolve, reject) => {
        db.query(updateSql, [localOrderId, orderID], (err) => {
          if (err) reject(err);
          resolve();
        });
      });
      res.json({ success: true });
    } else {
      res.status(400).json({ success: false, message: "Payment capture failed" });
    }
  } catch (error) {
    console.error("Capture payment error:", error);
    res.status(500).json({ success: false, message: "Failed to capture payment" });
  }
});

// 获取用户订单
app.get("/user-orders", (req, res) => {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ authenticated: false });

  jwt.verify(token, "secret_key", (err, decoded) => {
    if (err) return res.status(401).json({ authenticated: false });

    const sql = `
      SELECT o.orderId, o.totalPrice, o.status, o.createdAt, oi.pid, oi.quantity, oi.price, p.name
      FROM orders o
      LEFT JOIN order_items oi ON o.orderId = oi.orderId
      LEFT JOIN products p ON oi.pid = p.pid
      WHERE o.userId = ?
      ORDER BY o.createdAt DESC
      LIMIT 5`;
    db.query(sql, [decoded.userId], (err, results) => {
      if (err) {
        return res.status(500).json({ error: "Failed to fetch orders" });
      }

      const orders = {};
      results.forEach((row) => {
        if (!orders[row.orderId]) {
          orders[row.orderId] = {
            orderId: row.orderId,
            totalPrice: row.totalPrice,
            status: row.status,
            createdAt: row.createdAt,
            items: [],
          };
        }
        if (row.pid) {
          orders[row.orderId].items.push({
            pid: row.pid,
            name: row.name,
            price: row.price,
            quantity: row.quantity,
          });
        }
      });

      res.json(Object.values(orders));
    });
  });
});

// 获取所有订单（管理员）
app.get("/admin-orders", authenticateAdmin, (req, res) => {
  const sql = `
    SELECT o.orderId, o.username, o.totalPrice, o.status, o.createdAt, oi.pid, oi.quantity, oi.price, p.name
    FROM orders o
    LEFT JOIN order_items oi ON o.orderId = oi.orderId
    LEFT JOIN products p ON oi.pid = p.pid
    ORDER BY o.createdAt DESC`;
  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Failed to fetch orders" });
    }

    const orders = {};
    results.forEach((row) => {
      if (!orders[row.orderId]) {
        orders[row.orderId] = {
          orderId: row.orderId,
          username: row.username,
          totalPrice: row.totalPrice,
          status: row.status,
          createdAt: row.createdAt,
          items: [],
        };
      }
      if (row.pid) {
        orders[row.orderId].items.push({
          pid: row.pid,
          name: row.name,
          price: row.price,
          quantity: row.quantity,
        });
      }
    });

    res.json(Object.values(orders));
  });
});

const options = {
  key: fs.readFileSync(
    "/etc/letsencrypt/live/ierg4210.eastasia.cloudapp.azure.com/privkey.pem"
  ),
  cert: fs.readFileSync(
    "/etc/letsencrypt/live/ierg4210.eastasia.cloudapp.azure.com/fullchain.pem"
  ),
};

app.listen(3000, "127.0.0.1", () => {
  console.log("Node.js running on http://localhost:3000");
});