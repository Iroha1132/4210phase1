-- Create database
    CREATE DATABASE IF NOT EXISTS dummy_shop;
    USE dummy_shop;

    -- Create categories table
    CREATE TABLE IF NOT EXISTS categories (
        catid INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL
    );

    -- Create products table
    CREATE TABLE IF NOT EXISTS products (
        pid INT AUTO_INCREMENT PRIMARY KEY,
        catid INT NOT NULL,
        name VARCHAR(255) NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        description TEXT,
        image VARCHAR(255),
        thumbnail VARCHAR(255),
        FOREIGN KEY (catid) REFERENCES categories(catid)
    );

    -- Create users table
    CREATE TABLE IF NOT EXISTS users (
        userid INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        is_admin BOOLEAN NOT NULL DEFAULT FALSE,
        auth_token VARCHAR(255)
    );

    -- Create orders table
    CREATE TABLE IF NOT EXISTS orders (
        orderID INT AUTO_INCREMENT PRIMARY KEY,
        user_email VARCHAR(255),
        items JSON NOT NULL,
        total_price DECIMAL(10,2) NOT NULL,
        digest VARCHAR(255) NOT NULL,
        salt VARCHAR(32) NOT NULL,
        status ENUM('pending', 'completed', 'failed') NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE SET NULL
    );

    -- Create transactions table
    CREATE TABLE IF NOT EXISTS transactions (
        transaction_id INT AUTO_INCREMENT PRIMARY KEY,
        orderID INT NOT NULL,
        paypal_txn_id VARCHAR(255) NOT NULL,
        payment_status VARCHAR(50) NOT NULL,
        payment_amount DECIMAL(10,2) NOT NULL,
        currency_code VARCHAR(10) NOT NULL,
        payer_email VARCHAR(255),
        items JSON NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (orderID) REFERENCES orders(orderID)
    );

    -- Create messages table
    CREATE TABLE IF NOT EXISTS messages (
        message_id INT AUTO_INCREMENT PRIMARY KEY,
        user_email VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        admin_reply TEXT,
        replied_at TIMESTAMP NULL,
        FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE
    );

    -- Insert initial categories (only if table is empty)
    INSERT INTO categories (name)
    SELECT * FROM (SELECT 'Category1') AS tmp
    WHERE NOT EXISTS (SELECT name FROM categories WHERE name = 'Category1')
    LIMIT 1;

    INSERT INTO categories (name)
    SELECT * FROM (SELECT 'Category2') AS tmp
    WHERE NOT EXISTS (SELECT name FROM categories WHERE name = 'Category2')
    LIMIT 1;

    -- Insert initial products (only if table is empty)
    INSERT INTO products (catid, name, price, description, image, thumbnail)
    SELECT * FROM (
        SELECT 1, 'Product 1', 19.99, 'Default product description', '/images/product1.jpg', '/images/product1.jpg'
    ) AS tmp
    WHERE NOT EXISTS (SELECT name FROM products WHERE name = 'Product 1')
    LIMIT 1;

    INSERT INTO products (catid, name, price, description, image, thumbnail)
    SELECT * FROM (
        SELECT 1, 'Product 2', 29.99, 'Default product description', '/images/product2.jpg', '/images/product2.jpg'
    ) AS tmp
    WHERE NOT EXISTS (SELECT name FROM products WHERE name = 'Product 2')
    LIMIT 1;

    INSERT INTO products (catid, name, price, description, image, thumbnail)
    SELECT * FROM (
        SELECT 2, 'Product 3', 39.99, 'Default product description', '/images/product3.jpg', '/images/product3.jpg'
    ) AS tmp
    WHERE NOT EXISTS (SELECT name FROM products WHERE name = 'Product 3')
    LIMIT 1;

    INSERT INTO products (catid, name, price, description, image, thumbnail)
    SELECT * FROM (
        SELECT 2, 'Product 4', 49.99, 'Default product description', '/images/product4.jpg', '/images/product4.jpg'
    ) AS tmp
    WHERE NOT EXISTS (SELECT name FROM products WHERE name = 'Product 4')
    LIMIT 1;

    -- Insert initial users (only if table is empty)
    INSERT INTO users (email, password, is_admin)
    SELECT * FROM (
        SELECT 'admin@example.com', '$2b$10$Ndwr9eo190tkFcXYHrFAaeipj76aGoYtp8gRu9vi1rd7Gd/W8Bhx.', TRUE
    ) AS tmp
    WHERE NOT EXISTS (SELECT email FROM users WHERE email = 'admin@example.com')
    LIMIT 1;

    INSERT INTO users (email, password, is_admin)
    SELECT * FROM (
        SELECT 'user@example.com', '$2b$10$7pG43mC8YO2Qe7s1fgxFSe3wM1HM16i3.T9HFWzdZk0cF9fg6wPjG', FALSE
    ) AS tmp
    WHERE NOT EXISTS (SELECT email FROM users WHERE email = 'user@example.com')
    LIMIT 1;