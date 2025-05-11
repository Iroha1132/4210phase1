document.addEventListener('click', (event) => {
    if (event.target.classList.contains('add-to-cart')) {
        const productId = parseInt(event.target.getAttribute('data-pid'));
        fetch(`https://ierg4210.eastasia.cloudapp.azure.com/product/${productId}`)
            .then(response => {
                if (!response.ok) throw new Error('Product fetch failed');
                return response.json();
            })
            .then(product => {
                let cart = JSON.parse(localStorage.getItem('cart')) || [];
                const existingProduct = cart.find(item => item.pid === productId);

                if (existingProduct) {
                    existingProduct.quantity += 1;
                } else {
                    cart.push({ pid: productId, name: product.name, price: product.price, quantity: 1 });
                }

                localStorage.setItem('cart', JSON.stringify(cart));
                updateCartUI();
            })
            .catch(err => console.error('Cart add error:', err));
    }
});

// Function to sanitize PayPal form fields
function sanitizePayPalField(value) {
    return value.replace(/[^a-zA-Z0-9\s\-,.]/g, '');
}

function updateCartUI() {
    const cart = JSON.parse(localStorage.getItem('cart')) || [];
    const cartItems = document.querySelector('.cart-items');
    const cartButton = document.getElementById('cart-button');
    cartItems.innerHTML = '';

    let totalAmount = 0;
    const form = document.createElement('form');
    form.id = 'paypal-form';
    form.method = 'POST';
    form.action = 'https://www.sandbox.paypal.com/cgi-bin/webscr';

    // PayPal required hidden fields
    form.innerHTML = `
        <input type="hidden" name="cmd" value="_cart">
        <input type="hidden" name="upload" value="1">
        <input type="hidden" name="business" value="sb-7vfg240731629@business.example.com">
        <input type="hidden" name="charset" value="utf-8">
        <input type="hidden" name="currency_code" value="USD">
        <input type="hidden" name="invoice" id="invoice">
        <input type="hidden" name="custom" id="custom">
        <input type="hidden" name="return" value="https://ierg4210.eastasia.cloudapp.azure.com/?payment=success">
        <input type="hidden" name="notify_url" value="https://ierg4210.eastasia.cloudapp.azure.com/paypal-webhook">
    `;

    cart.forEach((item, index) => {
        totalAmount += item.price * item.quantity;
        const itemIndex = index + 1;
        const cartItem = document.createElement('li');
        cartItem.innerHTML = DOMPurify.sanitize(`
            ${item.name} - <input type="number" value="${item.quantity}" min="0" data-pid="${item.pid}"> x $${item.price}
        `);
        const sanitizedName = sanitizePayPalField(item.name);
        form.innerHTML += `
            <input type="hidden" name="item_name_${itemIndex}" value="${sanitizedName}">
            <input type="hidden" name="item_number_${itemIndex}" value="${item.pid}">
            <input type="hidden" name="amount_${itemIndex}" value="${item.price}">
            <input type="hidden" name="quantity_${itemIndex}" value="${item.quantity}">
            <input type="hidden" name="cancel_return" value="https://ierg4210.eastasia.cloudapp.azure.com/?payment=cancel">
            <input type="hidden" name="no_note" value="1"> <!-- 禁用备注 -->
            <input type="hidden" name="no_shipping" value="1"> <!-- 禁用配送 -->
        `;
        cartItems.appendChild(cartItem);
    });

    const totalElement = document.createElement('li');
    totalElement.className = 'total';
    totalElement.textContent = `Total: $${totalAmount.toFixed(2)}`;
    cartItems.appendChild(totalElement);

    const checkoutButton = document.createElement('button');
    checkoutButton.className = 'checkout';
    checkoutButton.textContent = 'Checkout';
    cartItems.appendChild(form);
    form.appendChild(checkoutButton);

    const totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
    cartButton.textContent = `Cart (${totalItems})`;
}

document.addEventListener('change', (event) => {
    if (event.target.tagName === 'INPUT' && event.target.type === 'number') {
        const pid = parseInt(event.target.getAttribute('data-pid'));
        const newQuantity = parseInt(event.target.value);
        let cart = JSON.parse(localStorage.getItem('cart')) || [];

        if (newQuantity <= 0) {
            cart = cart.filter(item => item.pid !== pid);
        } else {
            const product = cart.find(item => item.pid === pid);
            if (product) product.quantity = newQuantity;
        }

        localStorage.setItem('cart', JSON.stringify(cart));
        updateCartUI();
    }
});

document.addEventListener('click', (event) => {
    if (event.target.classList.contains('checkout')) {
        console.log('Checkout button clicked');
        event.preventDefault();
        const cart = JSON.parse(localStorage.getItem('cart')) || [];
        if (cart.length === 0) {
            alert('Cart is empty');
            return;
        }

        const items = cart.map(item => ({
            pid: parseInt(item.pid),
            quantity: item.quantity
        }));

        // 获取 CSRF token
        fetch('https://ierg4210.eastasia.cloudapp.azure.com/csrf-token', { credentials: 'include' })
            .then(response => {
                if (!response.ok) throw new Error('CSRF token fetch failed');
                return response.json();
            })
            .then(csrfData => {
                // 调用 /validate-order
                return fetch('https://ierg4210.eastasia.cloudapp.azure.com/validate-order', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfData.csrfToken
                    },
                    body: JSON.stringify({ items }),
                    credentials: 'include'
                });
            })
            .then(response => {
                if (!response.ok) {
                    console.error('Validate-order failed:', response.status, response.statusText);
                    throw new Error('Order validation failed: ' + response.statusText);
                }
                return response.json();
            })
            .then(data => {
                const form = document.getElementById('paypal-form');
                document.getElementById('invoice').value = data.orderID;
                document.getElementById('custom').value = data.digest;

                const formData = new FormData(form);
                const formDataObject = {};
                for (let [key, value] of formData.entries()) {
                    formDataObject[key] = value;
                }
                console.log('PayPal form data:', formDataObject);

                if (!formDataObject['item_name_1']) {
                    console.error('No cart items found in form data');
                    alert('Error: Cart items are missing.');
                    return;
                }

                // 提交表单
                form.submit();
                localStorage.removeItem('cart');
                updateCartUI();
            })
            .catch(err => {
                console.error('Checkout error:', err);
                alert('Checkout failed: ' + err.message);
            });
    }
});

document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('payment') === 'success') {
        alert('Payment successful! Thank you for your purchase.');
        history.replaceState({}, '', '/');
    } else if (urlParams.get('payment') === 'cancel') {
        alert('Payment was cancelled.');
        history.replaceState({}, '', '/');
    }
});

const cartButton = document.getElementById('cart-button');
const shoppingCart = document.getElementById('shopping-cart');
let hideTimeout;

// Show cart on mouseenter
cartButton.addEventListener('mouseenter', () => {
    clearTimeout(hideTimeout); // Cancel any pending hide action
    shoppingCart.classList.add('visible');
});

shoppingCart.addEventListener('mouseenter', () => {
    clearTimeout(hideTimeout); // Cancel any pending hide action
    shoppingCart.classList.add('visible');
});

// Hide cart after a delay on mouseleave
cartButton.addEventListener('mouseleave', () => {
    hideTimeout = setTimeout(() => {
        shoppingCart.classList.remove('visible');
    }, 300); // 300ms delay
});

shoppingCart.addEventListener('mouseleave', () => {
    hideTimeout = setTimeout(() => {
        shoppingCart.classList.remove('visible');
    }, 300); // 300ms delay
});

// Close cart immediately when clicking the close button
document.querySelector('.close-cart').addEventListener('click', () => {
    clearTimeout(hideTimeout); // Cancel any pending hide action
    shoppingCart.classList.remove('visible');
});

updateCartUI();