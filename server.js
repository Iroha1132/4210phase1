const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql");
const fetch = require("node-fetch");
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

const upload = multer({ dest: "uploads/" });
const app = express();

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: [
        "'self'",
        "data:",
        "https://ierg4210.eastasia.cloudapp.azure.com",
      ],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
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
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
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

  // 更新 orders 表，添加 salt 欄位並設置貨幣為 USD
  const updateOrdersTable = `
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS salt VARCHAR(32) NULL,
    MODIFY COLUMN currency VARCHAR(3) DEFAULT 'USD'
  `;
  db.query(updateOrdersTable, (err) => {
    if (err) console.error("Failed to update orders table:", err);
  });

  // 創建 orders 表
  const createOrdersTable = `
    CREATE TABLE IF NOT EXISTS orders (
      orderId INT AUTO_INCREMENT PRIMARY KEY,
      userId INT NULL,
      username VARCHAR(255) NULL,
      currency VARCHAR(3) DEFAULT 'USD',
      totalPrice DECIMAL(10,2) NOT NULL,
      digest VARCHAR(255) NOT NULL,
      salt VARCHAR(32) NULL,
      status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(userid)
    )`;
  db.query(createOrdersTable, (err) => {
    if (err) throw err;
  });

  // 創建 order_items 表
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
app.use(bodyParser.json({ type: "application/json" }));
app.use(express.raw({ type: "application/json" })); // 處理 Webhook 的原始 JSON
app.use(express.static(path.join(__dirname, "public")));

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
      return res.status(500).json({ success: false, message: "伺服器錯誤" });
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
      message: "郵箱或密碼錯誤" 
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
      return res.status(400).json({ success: false, message: "缺少必要欄位" });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: "新密碼必須至少8個字符" });
    }

    const sql = "SELECT password FROM users WHERE userid = ?";
    db.query(sql, [userId], (err, results) => {
      if (err) {
        console.error("資料庫錯誤:", err);
        return res.status(500).json({ success: false, message: "伺服器錯誤" });
      }

      if (results.length === 0) {
        return res.status(404).json({ success: false, message: "用戶未找到" });
      }

      const user = results[0];

      if (!bcrypt.compareSync(currentPassword, user.password)) {
        return res.status(401).json({ success: false, message: "當前密碼不正確" });
      }

      const hashedPassword = bcrypt.hashSync(newPassword, 10);

      const updateSql = "UPDATE users SET password = ? WHERE userid = ?";
      db.query(updateSql, [hashedPassword, userId], (err, result) => {
        if (err) {
          console.error("資料庫錯誤:", err);
          return res.status(500).json({ success: false, message: "更新密碼失敗" });
        }

        res.clearCookie("auth_token");
        res.json({ success: true, message: "密碼更改成功" });
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
        return res.status(404).json({ error: "用戶未找到" });
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
              res.send("產品已添加");
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
          res.send("產品已添加");
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
              res.send("產品已更新");
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
          res.send("產品已更新");
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
    res.send("類別已添加");
  });
});

app.put("/update-category/:catid", authenticateAdmin, (req, res) => {
  const catid = xss(req.params.catid);
  const { name } = req.body;
  const sanitizedName = xss(name);
  const sql = "UPDATE categories SET name = ? WHERE catid = ?";
  db.query(sql, [sanitizedName, catid], (err, result) => {
    if (err) throw err;
    res.send("類別已更新");
  });
});

app.delete("/delete-product/:pid", authenticateAdmin, (req, res) => {
  const pid = xss(req.params.pid);
  const sql = "DELETE FROM products WHERE pid = ?";
  db.query(sql, [pid], (err, result) => {
    if (err) throw err;
    res.send("產品已刪除");
  });
});

app.delete("/delete-category/:catid", authenticateAdmin, (req, res) => {
  const catid = xss(req.params.catid);
  const sql = "DELETE FROM categories WHERE catid = ?";
  db.query(sql, [catid], (err, result) => {
    if (err) throw err;
    res.send("類別已刪除");
  });
});

// 訂單驗證路由
app.post("/validate-order", csrfProtection, (req, res) => {
  const { items } = req.body;
  const token = req.cookies.auth_token;
  let userId = null;
  let username = "guest";

  if (token) {
    jwt.verify(token, "secret_key", (err, decoded) => {
      if (!err) {
        userId = decoded.userId;
        const sql = "SELECT email FROM users WHERE userid = ?";
        db.query(sql, [userId], (err, results) => {
          if (!err && results.length > 0) {
            username = results[0].email;
          }
        });
      }
    });
  }

  const pids = items.map((item) => xss(item.pid));
  const quantities = items.map((item) => parseInt(item.quantity));
  if (quantities.some((q) => q <= 0)) {
    return res.json({ success: false, message: "無效的數量" });
  }

  const sql = "SELECT pid, price FROM products WHERE pid IN (?)";
  db.query(sql, [pids], (err, results) => {
    if (err || results.length !== pids.length) {
      return res.json({ success: false, message: "無效的產品" });
    }

    const prices = {};
    results.forEach((row) => {
      prices[row.pid] = row.price;
    });

    let totalPrice = 0;
    items.forEach((item) => {
      totalPrice += prices[item.pid] * item.quantity;
    });

    const salt = crypto.randomBytes(16).toString("hex");
    const dataToHash = [
      "USD",
      "sb-7vfg240731629@business.example.com",
      salt,
      ...items.map((item) => `${item.pid}:${item.quantity}:${prices[item.pid]}`),
      totalPrice.toFixed(2),
    ].join("|");
    const digest = crypto.createHash("sha256").update(dataToHash).digest("hex");

    const orderSql = "INSERT INTO orders (userId, username, totalPrice, digest, salt, status) VALUES (?, ?, ?, ?, ?, 'pending')";
    db.query(orderSql, [userId, username, totalPrice, digest, salt], (err, result) => {
      if (err) {
        console.error("訂單創建錯誤:", err);
        return res.json({ success: false, message: "訂單創建失敗" });
      }

      const orderId = result.insertId;
      const itemSql = "INSERT INTO order_items (orderId, pid, quantity, price) VALUES ?";
      const itemValues = items.map((item) => [
        orderId,
        item.pid,
        item.quantity,
        prices[item.pid],
      ]);

      db.query(itemSql, [itemValues], (err) => {
        if (err) {
          console.error("訂單項目創建錯誤:", err);
          return res.json({ success: false, message: "訂單項目創建失敗" });
        }
        res.json({ success: true, orderId, digest });
      });
    });
  });
});

// PayPal Webhook 路由
app.post("/paypal-webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const webhookEvent = req.body;

  // 將 Webhook 數據轉為表單格式並發送 IPN 驗證請求
  const formData = new URLSearchParams();
  formData.append("cmd", "_notify-validate");
  for (const key in webhookEvent) {
    if (Object.prototype.hasOwnProperty.call(webhookEvent, key)) {
      formData.append(key, webhookEvent[key]);
    }
  }

  try {
    const response = await fetch("https://www.sandbox.paypal.com/cgi-bin/webscr", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: formData.toString(),
    });

    const responseText = await response.text();

    if (responseText !== "VERIFIED") {
      console.error("IPN 驗證失敗:", responseText);
      return res.status(400).send("IPN 驗證失敗");
    }

    if (webhookEvent.event_type === "CHECKOUT.ORDER.APPROVED") {
      const orderId = webhookEvent.resource.custom_id;

      const checkSql = "SELECT status FROM orders WHERE orderId = ?";
      db.query(checkSql, [orderId], (err, results) => {
        if (err || !results.length || results[0].status !== "pending") {
          console.error("訂單已處理或無效:", err || results);
          return res.status(400).send("訂單已處理或無效");
        }

        const orderSql = "SELECT * FROM orders WHERE orderId = ?";
        db.query(orderSql, [orderId], (err, orderResults) => {
          if (err || !orderResults.length) {
            console.error("訂單未找到:", err);
            return res.status(400).send("訂單未找到");
          }

          const order = orderResults[0];
          const itemsSql = "SELECT * FROM order_items WHERE orderId = ?";
          db.query(itemsSql, [orderId], (err, itemResults) => {
            if (err) {
              console.error("訂單項目未找到:", err);
              return res.status(400).send("訂單項目未找到");
            }

            const dataToHash = [
              order.currency,
              "sb-7vfg240731629@business.example.com",
              order.salt,
              ...itemResults.map((item) => `${item.pid}:${item.quantity}:${item.price}`),
              order.totalPrice.toFixed(2),
            ].join("|");
            const newDigest = crypto.createHash("sha256").update(dataToHash).digest("hex");

            if (newDigest !== order.digest) {
              console.error("Digest 驗證失敗:", { newDigest, storedDigest: order.digest });
              return res.status(400).send("Digest 驗證失敗");
            }

            const updateSql = "UPDATE orders SET status = 'completed' WHERE orderId = ?";
            db.query(updateSql, [orderId], (err) => {
              if (err) {
                console.error("更新訂單狀態失敗:", err);
                return res.status(500).send("更新訂單狀態失敗");
              }
              console.log("Webhook 已處理，訂單:", orderId);
              res.status(200).send("Webhook 已處理");
            });
          });
        });
      });
    } else {
      console.log("忽略的 Webhook 事件:", webhookEvent.event_type);
      res.status(200).send("忽略的 Webhook 事件");
    }
  } catch (err) {
    console.error("IPN 驗證錯誤:", err);
    return res.status(500).send("IPN 驗證錯誤");
  }
});

// 獲取用戶訂單
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
        return res.status(500).json({ error: "無法獲取訂單" });
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

// 獲取所有訂單（管理員）
app.get("/admin-orders", authenticateAdmin, (req, res) => {
  const sql = `
    SELECT o.orderId, o.username, o.totalPrice, o.status, o.createdAt, oi.pid, oi.quantity, oi.price, p.name
    FROM orders o
    LEFT JOIN order_items oi ON o.orderId = oi.orderId
    LEFT JOIN products p ON oi.pid = p.pid
    ORDER BY o.createdAt DESC`;
  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ error: "無法獲取訂單" });
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