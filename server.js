require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const app = express();

app.use(express.json());
app.use(require('cors')());
app.use(express.static(__dirname));

const dataPath = path.join(__dirname, 'data.json');
const sessionSecret = process.env.SESSION_SECRET || 'change-this-session-secret';
const adminEmail = process.env.ADMIN_EMAIL || 'admin@antarctica.local';
const adminPassword = process.env.ADMIN_PASSWORD || 'change-this-admin-password';

function readData() {
    try {
        const data = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
        return { users: [], orders: [], pendingRegistrations: {}, passwordResets: {}, rates: {}, ...data };
    } catch (error) {
        return { users: [], orders: [], pendingRegistrations: {}, passwordResets: {}, rates: {} };
    }
}

function writeData(data) {
    fs.writeFileSync(dataPath, JSON.stringify(data, null, 2));
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
    const [salt, expected] = String(storedHash || '').split(':');
    if (!salt || !expected) return false;
    const actual = crypto.scryptSync(password, salt, 64).toString('hex');
    const expectedBuffer = Buffer.from(expected);
    const actualBuffer = Buffer.from(actual);
    return expectedBuffer.length === actualBuffer.length && crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

function createToken(payload) {
    const encoded = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 })).toString('base64url');
    const signature = crypto.createHmac('sha256', sessionSecret).update(encoded).digest('base64url');
    return `${encoded}.${signature}`;
}

function getAuth(req) {
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!token) return null;
    const [encoded, signature] = token.split('.');
    if (!encoded || !signature) return null;
    const expected = crypto.createHmac('sha256', sessionSecret).update(encoded).digest('base64url');
    if (signature !== expected) return null;
    try {
        const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
        return payload.exp > Date.now() ? payload : null;
    } catch (error) {
        return null;
    }
}

function requireAuth(req, res, next) {
    const auth = getAuth(req);
    if (!auth) return res.status(401).json({ error: 'Authentication required' });
    req.auth = auth;
    next();
}

function requireAdmin(req, res, next) {
    if (!req.auth || req.auth.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    next();
}

function publicUser(user) {
    return { id: user.id, name: user.name, email: user.email, phone: user.phone, avatar: user.avatar, createdAt: user.createdAt };
}

// Auth Routes
app.post('/api/auth/register/request', async (req, res) => {
    const { name, phone, email, password } = req.body || {};
    if (!name || !phone || !email || !password || password.length < 6) return res.status(400).json({ error: 'Name, phone, email and a 6-character password are required' });
    const data = readData();
    const normalizedEmail = email.trim().toLowerCase();
    if (data.users.some(user => user.email === normalizedEmail)) return res.status(409).json({ error: 'Email is already registered' });
    const otp = String(crypto.randomInt(100000, 1000000));
    data.pendingRegistrations[normalizedEmail] = { name: name.trim(), phone: phone.trim(), email: normalizedEmail, passwordHash: hashPassword(password), otpHash: hashPassword(otp), expiresAt: Date.now() + 10 * 60 * 1000, attempts: 0 };
    writeData(data);
    res.json({ pending: true, debugOtp: otp });
});

app.post('/api/auth/register/verify', (req, res) => {
    const { email, otp } = req.body || {};
    const data = readData();
    const pending = data.pendingRegistrations[String(email || '').trim().toLowerCase()];
    if (!pending || pending.expiresAt < Date.now() || pending.attempts >= 5) return res.status(400).json({ error: 'Invalid or expired verification code' });
    if (!verifyPassword(String(otp || ''), pending.otpHash)) {
        pending.attempts += 1;
        writeData(data);
        return res.status(400).json({ error: 'Invalid or expired verification code' });
    }
    const user = { id: crypto.randomUUID(), name: pending.name, phone: pending.phone, email: pending.email, passwordHash: pending.passwordHash, avatar: 'logo.png', createdAt: new Date().toISOString() };
    data.users.push(user);
    delete data.pendingRegistrations[pending.email];
    writeData(data);
    res.status(201).json({ user: publicUser(user), token: createToken({ userId: user.id, role: 'customer', email: user.email }) });
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body || {};
    if (email === adminEmail && password === adminPassword) return res.json({ user: { name: 'Admin', email: adminEmail, role: 'admin' }, token: createToken({ userId: 'admin', role: 'admin', email: adminEmail }) });
    const user = readData().users.find(item => item.email === String(email || '').trim().toLowerCase());
    if (!user || !verifyPassword(password || '', user.passwordHash)) return res.status(401).json({ error: 'Invalid email or password' });
    res.json({ user: publicUser(user), token: createToken({ userId: user.id, role: 'customer', email: user.email }) });
});

app.get('/api/me', requireAuth, (req, res) => {
    if (req.auth.role === 'admin') return res.json({ user: { name: 'Admin', email: adminEmail, role: 'admin' } });
    const user = readData().users.find(item => item.id === req.auth.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user: publicUser(user) });
});

app.get('/api/rates', (req, res) => res.json({ rates: readData().rates || {} }));

app.get('/api/orders', requireAuth, (req, res) => {
    const orders = readData().orders;
    res.json({ orders: req.auth.role === 'admin' ? orders : orders.filter(order => order.userId === req.auth.userId) });
});

app.post('/api/orders', requireAuth, (req, res) => {
    const productUrl = String(req.body.url || req.body.productUrl || req.body.link || '').trim();
    const order = { ...req.body, url: productUrl, productUrl, id: Date.now(), userId: req.auth.userId, userEmail: req.auth.email || '', adminPrice: '', status: 'pending', orderStatus: 'pending', priceStatus: 'pending', date: new Date().toISOString() };
    const data = readData();
    data.orders.push(order);
    writeData(data);
    res.status(201).json({ order });
});

// ==========================================
// Scraper API السريع والمتجاوز للحظر
// ==========================================
async function handleScrape(targetUrl, res) {
    if (!targetUrl) return res.status(400).json({ success: false, error: 'Url is required' });

    try {
        // استخدام خدمة OpenGraph API مجانية ومباشرة
        const apiUrl = `https://api.dub.co/metatags?url=${encodeURIComponent(targetUrl)}`;
        const response = await fetch(apiUrl);
        const data = await response.json();

        if (data && (data.image || data.title)) {
            return res.json({
                success: true,
                data: {
                    title: data.title || 'منتج من المتجر',
                    image: data.image || 'logo.png',
                    price: 0,
                    url: targetUrl
                }
            });
        }

        return res.json({ success: false });
            
    } catch (err) {
        console.error('Scrape Error:', err);
        return res.json({
            success: true,
            data: { title: 'تم إرفاق الرابط بنجاح', image: 'logo.png', price: 0, url: targetUrl }
        });
    }
}
        
        // خيار احتياطي في حال بطء المتصفح السحابي
        return res.json({
            success: true,
            data: {
                title: 'تم التعرف على الرابط',
                image: '',
                price: 0,
                url: targetUrl
            }
        });
    }
}
app.post('/api/scrape', async (req, res) => {
    const url = req.body ? (req.body.url || req.body.link || req.body.productUrl) : null;
    await handleScrape(url, res);
});

app.get('/api/scrape', async (req, res) => {
    const url = req.query ? req.query.url : null;
    await handleScrape(url, res);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
