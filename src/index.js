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
    console.error('ERROR: JWT_SECRET or REFRESH_TOKEN_SECRET is not set in your .env file!');
    process.exit(1);
}

app.use(express.json());
app.use(cookieParser());

const corsOptions = {
    origin: FRONTEND_URL,
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

app.use(express.static(path.join(__dirname, '../public')));

const targets = new Map();

function scheduleCheckForTarget(target) {
    if (targets.has(target.id)) {
        clearInterval(targets.get(target.id).job);
    }

    const task = async () => {
        let up = false, statusCode = null, responseTimeMs = null;
        const start = Date.now();

        const controller = new AbortController();
        const timeout = setTimeout(() => {
            controller.abort();
        }, 15000);

        try {
            const r = await fetch(target.url, { signal: controller.signal });
            responseTimeMs = Date.now() - start;
            statusCode = r.status;
            up = r.ok;
        } catch (e) {
            up = false;
            statusCode = null;
            responseTimeMs = null;
        } finally {
            clearTimeout(timeout);
        }
        
        try {
            const checkResult = {
                targetId: target.id,
                up,
                statusCode,
                responseTimeMs,
            };
            await prisma.targetCheck.create({
                data: checkResult
            });

            const targetInfo = targets.get(target.id);
            if (targetInfo) {
                targetInfo.history.push({ ...checkResult, timestamp: new Date() });
                if (targetInfo.history.length > 50) {
                    targetInfo.history.shift();
                }
            }

        } catch (e) {
            console.error(`[DB Error] Failed to store check for target ${target.id}:`, e);
        }
    };

    const intervalId = setInterval(task, target.intervalSeconds * 1000);

    task(); 

    targets.set(target.id, {
        name: target.name,
        url: target.url,
        intervalSeconds: target.intervalSeconds,
        job: intervalId,
        history: []
    });
}

function chargeUser(cost, type = 'unknown') {
    return async (req, res, next) => {
        if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
            const usage = await prisma.userUsage.findUnique({ where: { userId: req.user.id } });
        
        if (!usage || usage.credits < cost) {
            return res.status(429).json({
                message: `Not enough credits. (${usage?.credits?.toFixed(2) || 0} left)`
            });
        }

        await prisma.$transaction([
            prisma.userUsage.update({
                where: { userId: req.user.id },
                data: { credits: { decrement: cost } }
            }),
            prisma.UserUsageLog.create({
                data: {
                    userId: req.user.id,
                    type,
                    cost
                }
            })
        ]);

        next();
    };
}

function generateAccessToken(user) {
    return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRATION });
}

async function generateRefreshToken(user) {
    const token = jwt.sign({ id: user.id }, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRATION });
    let expiresInMs = 7 * 24 * 60 * 60 * 1000;
    try {
        const val = parseInt(REFRESH_TOKEN_EXPIRATION.slice(0, -1));
        const unit = REFRESH_TOKEN_EXPIRATION.slice(-1);
        if (unit === 'm') expiresInMs = val * 60 * 1000;
        else if (unit === 'h') expiresInMs = val * 60 * 60 * 1000;
        else if (unit === 'd') expiresInMs = val * 24 * 60 * 60 * 1000;
    } catch {}
    await prisma.refreshToken.create({
        data: { token, userId: user.id, expiresAt: new Date(Date.now() + expiresInMs) }
    });
    return token;
}

function authenticateToken(req, res, next) {
    const accessToken = req.cookies.accessToken;
    if (!accessToken) return res.status(401).json({ message: 'Authentication required. No access token provided.' });
    jwt.verify(accessToken, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Access token invalid or expired.' });
        req.user = user;
        next();
    });
}

app.get('/api/status', (req, res) => res.send('🟢 Obserpoint Backend is alive!'));

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || !/^\w{3,20}$/.test(username)) {
        return res.status(400).json({ message: 'Invalid username or password format.' });
    }
    if (await prisma.user.findUnique({ where: { username } })) {
        return res.status(409).json({ message: 'Username already taken.' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    await prisma.user.create({ data: { username, passwordHash } });
    res.status(201).json({ message: 'Registered successfully!' });
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await prisma.user.findUnique({ where: { username } });
        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        const accessToken = generateAccessToken(user);
        const refreshToken = await generateRefreshToken(user);
        const cookieOptions = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax' };
        res.cookie('accessToken', accessToken, { ...cookieOptions, maxAge: 15 * 60 * 1000 });
        res.cookie('refreshToken', refreshToken, { ...cookieOptions, maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.status(200).json({ message: 'Logged in successfully' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'An internal server error occurred.' });
    }
});

app.post('/refresh-token', async (req, res) => {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ message: 'No refresh token provided.' });
    const stored = await prisma.refreshToken.findUnique({ where: { token } });
    if (!stored || stored.expiresAt.getTime() < Date.now()) {
        if(stored) await prisma.refreshToken.delete({ where: { token } });
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');
        return res.status(403).json({ message: 'Refresh token expired or invalid.' });
    }
    const user = await prisma.user.findUnique({ where: { id: stored.userId } });
    if (!user) return res.status(403).json({ message: 'User not found.' });
    const accessToken = generateAccessToken(user);
    res.cookie('accessToken', accessToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', maxAge: 15 * 60 * 1000 });
    res.status(200).json({ message: 'Access token refreshed!' });
});

app.post('/logout', async (req, res) => {
    const token = req.cookies.refreshToken;
    if (token) await prisma.refreshToken.deleteMany({ where: { token } });
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.status(200).json({ message: 'Logged out successfully!' });
});

app.get('/protected', authenticateToken, (req, res) => res.json({ message: `Welcome, ${req.user.username}!`, ...req.user }));

app.get('/user/profile', authenticateToken, async (req, res) => {
    const user = await prisma.user.findUnique({ where: { id: req.user.id }, select: { username: true, email: true } });
    res.json(user);
});

app.patch('/user/profile', authenticateToken, async (req, res) => {
    const { email } = req.body || {};
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ message: 'Invalid email format.' });
    const updated = await prisma.user.update({
        where: { id: req.user.id },
        data: { email: email || null },
        select: { username: true, email: true }
    });
    res.json(updated);
});

app.get('/user/usage', authenticateToken, async (req, res) => {
    const usage = await prisma.userUsage.findUnique({ where: { userId: req.user.id } });
    if (!usage) return res.json({ credits: 3000, resetAt: null });
    res.json({ credits: usage.credits, resetAt: usage.resetAt });
});

app.get('/user/usage-log', authenticateToken, async (req, res) => {
    const logs = await prisma.userUsageLog.findMany({
        where: { userId: req.user.id },
        orderBy: { timestamp: 'asc' }
    });

    const usageByDay = {};

    for (const log of logs) {
        const date = log.timestamp.toISOString().slice(0, 10);
        if (!usageByDay[date]) usageByDay[date] = {};
        usageByDay[date][log.type] = (usageByDay[date][log.type] || 0) + log.cost;
    }

    const result = Object.entries(usageByDay).map(([date, types]) => ([
        date,
        ...types
    ]));

    res.json(result);
});

app.get('/user/usage-breakdown', authenticateToken, async (req, res) => {
    const logs = await prisma.userUsageLog.findMany({
        where: { userId: req.user.id }
    });

    const breakdown = {};
    for (const { type, cost } of logs) {
        breakdown[type] = (breakdown[type] || 0) + cost;
    }

    res.json(breakdown);
});

app.post('/targets', authenticateToken, chargeUser(2, 'Create'), async (req, res) => {
    const { name, url, intervalSeconds } = req.body;
    if (!name || !url || !intervalSeconds) return res.status(400).json({ error: 'name, url and intervalSeconds are required' });
    const created = await prisma.target.create({
        data: { name, url, intervalSeconds, userId: req.user.id }
    });
    scheduleCheckForTarget(created);
    res.status(201).json({ targetId: created.id });
});

const getTargetsResponse = (targets) => targets.map(t => {
    const latest = t.checks[0] || {};
    return {
        targetId: t.id,
        name: t.name,
        url: t.url,
        status: latest.up === false ? 'down' : (latest.up === true ? 'up' : 'pending'),
        lastCheck: latest.timestamp || null,
        responseTimeMs: latest.responseTimeMs
    };
});

app.get('/targets', authenticateToken, chargeUser(1.5, 'Mass get'), async (req, res) => {
    const userTargets = await prisma.target.findMany({
        where: { userId: req.user.id },
        include: { checks: { orderBy: { timestamp: 'desc' }, take: 1 } }
    });
    res.json(getTargetsResponse(userTargets));
});

app.get('/targets/:id/checks', authenticateToken, chargeUser(1, 'Get'), async (req, res) => {
    const targetId = parseInt(req.params.id);
    const target = await prisma.target.findFirst({ where: { id: targetId, userId: req.user.id } });
    if (!target) return res.status(403).json({ message: 'Access denied.' });
    const checks = await prisma.targetCheck.findMany({ where: { targetId }, orderBy: { timestamp: 'desc' }, take: 50 });
    res.json(checks);
});

app.delete('/targets/:id', authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id);
    const target = await prisma.target.findFirst({ where: { id, userId: req.user.id } });
    if (!target) return res.status(403).json({ message: 'Access denied.' });

    if (targets.has(id)) {
        clearInterval(targets.get(id).job);
        targets.delete(id);
    }
    
    await prisma.targetCheck.deleteMany({ where: { targetId: id } });
    await prisma.target.delete({ where: { id } });
    res.status(200).json({ message: 'Target deleted.' });
});

app.get('/demo-targets', async (req, res) => {
    const demoTargets = await prisma.target.findMany({
        where: { userId: null },
        include: { checks: { orderBy: { timestamp: 'desc' }, take: 1 } }
    });
    res.json(getTargetsResponse(demoTargets));
});

app.get('/demo-targets/:id/checks', async (req, res) => {
    const targetId = parseInt(req.params.id);
    const target = await prisma.target.findFirst({ where: { id: targetId, userId: null } });
    if (!target) return res.status(403).json({ message: 'Access denied. Not a demo target.' });
    const checks = await prisma.targetCheck.findMany({ where: { targetId }, orderBy: { timestamp: 'desc' }, take: 50 });
    res.json(checks);
});

async function setupDemoTargets() {
    console.log('Checking for and setting up demo targets...');
    const demoData = [
        { name: "Google", url: "https://www.google.com", intervalSeconds: 30 },
        { name: "Youtube", url: "https://www.youtube.com", intervalSeconds: 30 },
        { name: "Twitch", url: "https://twitch.tv", intervalSeconds: 30 },
        { name: "Facebook", url: "https://www.facebook.com", intervalSeconds: 30 },
        { name: "Reeedit", url: "https://www.reeeddit.com", intervalSeconds: 30 },
        { name: "Wikipedia", url: "https://www.wikipedia.org", intervalSeconds: 30 },
    ];

    for (const d of demoData) {
        const existing = await prisma.target.findFirst({ where: { url: d.url, userId: null } });

        if (existing) {
            console.log(`Already exists: ${d.name}`);
            scheduleCheckForTarget(existing);
        } else {
            const created = await prisma.target.create({ data: { ...d, userId: null } });
            console.log(`Created demo target: ${d.name}`);
            scheduleCheckForTarget(created);
        }
    }
}

async function initializeMonitoringJobs() {
    console.log('Initializing monitoring jobs for all targets in the database...');
    const allTargets = await prisma.target.findMany();
    allTargets.forEach(scheduleCheckForTarget);
    console.log(`Initialization complete. Started ${allTargets.length} monitoring jobs.`);
}

cron.schedule('* * * * *', async () => {
    const now = new Date();
    try {
        const expired = await prisma.userUsage.findMany({
            where: { resetAt: { lt: now } }
        });

        if (expired.length) {
            await Promise.all(expired.map(u =>
                prisma.userUsage.update({
                    where: { userId: u.userId },
                    data: {
                        credits: 3000,
                        resetAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
                    }
                })
            ));
            console.log(`Reset ${expired.length} users' credits at ${now.toISOString()}`);
        }
    } catch (e) {
        console.error('[Usage Reset Job] error:', e);
    }
});

app.listen(PORT, async (err) => {
    if (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
    }
    console.log(`Obserpoint backend listening on http://localhost:${PORT}`);

    await setupDemoTargets();
    await initializeMonitoringJobs();

    console.log(`Frontend served from '../public' and expected at: ${FRONTEND_URL}`);
});