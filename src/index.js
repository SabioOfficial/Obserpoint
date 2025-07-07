require('dotenv').config();

process.on('uncaughtException', console.error);
process.on('unhandledRejection', console.error);

const cron = require('node-cron');
const express = require('express');
const fetch = require('node-fetch');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult, param } = require('express-validator');

const app = express();

const PORT = process.env.PORT || 4893;
const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const ACCESS_TOKEN_EXPIRATION = process.env.ACCESS_TOKEN_EXPIRATION || '15m';
const REFRESH_TOKEN_EXPIRATION = process.env.REFRESH_TOKEN_EXPIRATION || '7d';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5500';

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

if (!JWT_SECRET || !REFRESH_TOKEN_SECRET) {
    console.error('FATAL ERROR: JWT_SECRET or REFRESH_TOKEN_SECRET is not set in your .env file.');
    process.exit(1);
}

app.use(express.json());
app.use(cookieParser());
app.use(helmet());

const corsOptions = {
    origin: FRONTEND_URL,
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

app.use(express.static(path.join(__dirname, '../public')));

const apiLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 100,
	standardHeaders: true,
	legacyHeaders: false,
});
app.use(apiLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { message: 'Too many authentication attempts from this IP, please try again after 15 minutes' },
    standardHeaders: true,
	legacyHeaders: false,
});

const targets = new Map();

function generateAccessToken(user) {
    return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRATION });
}

function parseDuration(durationStr) {
    if (typeof durationStr !== 'string') return 7 * 24 * 60 * 60 * 1000;
    const unit = durationStr.slice(-1);
    const val = parseInt(durationStr.slice(0, -1), 10);
    if (isNaN(val)) return 7 * 24 * 60 * 60 * 1000;
    switch (unit) {
        case 's': return val * 1000;
        case 'm': return val * 60 * 1000;
        case 'h': return val * 60 * 60 * 1000;
        case 'd': return val * 24 * 60 * 60 * 1000;
        default: return 7 * 24 * 60 * 60 * 1000;
    }
}

async function generateAndStoreRefreshToken(user, oldToken = null) {
    if (oldToken) {
        await prisma.refreshToken.deleteMany({ where: { token: oldToken } });
    }

    const token = jwt.sign({ id: user.id }, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRATION });
    const expiresInMs = parseDuration(REFRESH_TOKEN_EXPIRATION);

    await prisma.refreshToken.create({
        data: {
            token,
            userId: user.id,
            expiresAt: new Date(Date.now() + expiresInMs)
        }
    });
    return token;
}

function authenticateToken(req, res, next) {
    const accessToken = req.cookies.accessToken;
    if (!accessToken) return res.status(401).json({ message: 'Authentication required.' });

    jwt.verify(accessToken, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Access token invalid or expired.' });
        req.user = user;
        next();
    });
}

const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

app.get('/', (req, res) => res.send('🟢 Obserpoint Backend is alive!'));

const registerValidation = [
    body('username').trim().isLength({ min: 3, max: 20 }).withMessage('Username must be between 3 and 20 characters').isAlphanumeric().withMessage('Username must be alphanumeric.'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long.'),
];

app.post('/register', authLimiter, registerValidation, validate, async (req, res) => {
    const { username, password } = req.body;
    
    const existing = await prisma.user.findUnique({
        where: { username: username }
    });
    if (existing) {
        return res.status(409).json({ message: 'Username already taken.' });
    }

    const hash = await bcrypt.hash(password, 10);
    await prisma.user.create({ data: { username, passwordHash: hash } });
    res.status(201).json({ message: 'Registered successfully!' });
});

const loginValidation = [
    body('username').notEmpty().withMessage('Username is required.'),
    body('password').notEmpty().withMessage('Password is required.'),
];
app.post('/login', authLimiter, loginValidation, validate, async (req, res) => {
    const { username, password } = req.body;

    const user = await prisma.user.findUnique({
        where: { username: username }
    });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = await generateAndStoreRefreshToken(user);

    const cookieOptions = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax' };
    res.cookie('accessToken', accessToken, { ...cookieOptions, maxAge: parseDuration(ACCESS_TOKEN_EXPIRATION) });
    res.cookie('refreshToken', refreshToken, { ...cookieOptions, maxAge: parseDuration(REFRESH_TOKEN_EXPIRATION) });
    
    res.status(200).json({ message: 'Logged in successfully!' });
});

app.post('/refresh-token', async (req, res) => {
    const oldToken = req.cookies.refreshToken;
    if (!oldToken) return res.status(401).json({ message: 'No refresh token provided.' });

    const stored = await prisma.refreshToken.findUnique({ where: { token: oldToken } });
    if (!stored || stored.expiresAt.getTime() < Date.now()) {
        if (stored) await prisma.refreshToken.delete({ where: { token: oldToken } });
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');
        return res.status(403).json({ message: 'Refresh token expired or invalid.' });
    }

    const user = await prisma.user.findUnique({ where: { id: stored.userId } });
    if (!user) {
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');
        return res.status(403).json({ message: 'User not found.' });
    }
    
    const accessToken = generateAccessToken(user);
    const refreshToken = await generateAndStoreRefreshToken(user, oldToken);

    const cookieOptions = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax' };
    res.cookie('accessToken', accessToken, { ...cookieOptions, maxAge: parseDuration(ACCESS_TOKEN_EXPIRATION) });
    res.cookie('refreshToken', refreshToken, { ...cookieOptions, maxAge: parseDuration(REFRESH_TOKEN_EXPIRATION) });

    res.status(200).json({ message: 'Access token refreshed!' });
});

app.post('/logout', async (req, res) => {
    const token = req.cookies.refreshToken;
    if (token) {
        await prisma.refreshToken.deleteMany({ where: { token } });
    }
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.status(200).json({ message: 'Logged out successfully!' });
});

app.get('/protected', authenticateToken, (req, res) => {
    res.status(200).json({ message: `Welcome, ${req.user.username}! You have access to protected data.`, userId: req.user.id });
});

const targetValidation = [
    body('name').trim().isLength({ min: 1, max: 50 }).withMessage('Name is required and must be less than 50 characters.'),
    body('url').isURL().withMessage('A valid URL is required.'),
    body('intervalSeconds').isInt({ min: 10, max: 3600 }).withMessage('Interval must be an integer between 10 and 3600 seconds.')
];
app.post('/targets', authenticateToken, targetValidation, validate, async (req, res) => {
    const { name, url, intervalSeconds } = req.body;

    const newTarget = await prisma.target.create({
        data: { name, url, intervalSeconds, userId: req.user.id }
    });
    startMonitoringJob(newTarget);
    console.log(`User ${req.user.username} created target: ${name} (ID: ${newTarget.id})`);
    res.status(201).json({ message: "Target created!", targetId: newTarget.id });
});

app.get('/targets', authenticateToken, async (req, res) => {
    const userTargets = await prisma.target.findMany({ where: { userId: req.user.id } });
    const list = userTargets.map(dbTarget => {
        const liveTarget = targets.get(dbTarget.id);
        const latest = liveTarget ? (liveTarget.history[0] || {}) : {};
        return {
            targetId: dbTarget.id, name: dbTarget.name, url: dbTarget.url,
            status: latest.up === false ? 'down' : (latest.up === true ? 'up' : 'pending'),
            lastCheck: latest.timestamp || null, responseTimeMs: latest.responseTimeMs || null
        };
    });
    res.json(list);
});

const checksValidation = [
    param('id').isInt().withMessage('Target ID must be an integer.')
];
app.get('/targets/:id/checks', authenticateToken, checksValidation, validate, async (req, res) => {
    const id = parseInt(req.params.id, 10);

    const targetInDb = await prisma.target.findFirst({ where: { id, userId: req.user.id } });
    if (!targetInDb) return res.status(404).json({ message: "Target not found or access denied." });

    const target = targets.get(id);
    if (!target) return res.status(404).json({ message: "Target found but is not currently monitored." });

    res.json(target.history.slice(0, 50));
});

function startMonitoringJob(targetData) {
    if (targets.has(targetData.id)) return;

    const history = [];
    const job = cron.schedule(`*/${targetData.intervalSeconds} * * * * *`, async () => {
        const start = Date.now();
        let up = false, statusCode = null;
        try {
            const r = await fetch(targetData.url, { timeout: 10000 });
            statusCode = r.status;
            up = r.ok;
        } catch { up = false; }
        history.unshift({ timestamp: new Date().toISOString(), statusCode, responseTimeMs: Date.now() - start, up });
        if (history.length > 1000) history.pop();
    });
    job.start();
    targets.set(targetData.id, { ...targetData, job, history });
    console.log(`Started monitoring for target: ${targetData.name} (ID: ${targetData.id})`);
}

async function loadTargetsFromDb() {
    console.log('Loading targets from database...');
    const dbTargets = await prisma.target.findMany();
    for (const target of dbTargets) {
        startMonitoringJob(target);
    }
    console.log(`Loaded and started monitoring for ${dbTargets.length} targets.`);
}

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'An unexpected error occurred on the server.' });
});

app.listen(PORT, (err) => {
    if (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
    }
    console.log(`obserpoint backend listening on http://localhost:${PORT}`);
    console.log(`Frontend expected at: ${FRONTEND_URL}`);
    loadTargetsFromDb();
});