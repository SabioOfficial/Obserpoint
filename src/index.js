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

const { PrismaClient, Prisma } = require('@prisma/client');
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

let nextTargetId = 1;
const targets = new Map();

function generateAccessToken(user) {
    return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
        expiresIn: ACCESS_TOKEN_EXPIRATION
    });
}

async function generateRefreshToken(user) {
    const token = jwt.sign({ id: user.id }, REFRESH_TOKEN_SECRET, {
        expiresIn: REFRESH_TOKEN_EXPIRATION
    });

    let expiresInMs = 7 * 24 * 60 * 60 * 1000;
    try {
        const val = parseInt(REFRESH_TOKEN_EXPIRATION.slice(0, -1));
        const unit = REFRESH_TOKEN_EXPIRATION.slice(-1);
        if (unit === 'm') expiresInMs = val * 60 * 1000;
        else if (unit === 'h') expiresInMs = val * 60 * 60 * 1000;
        else if (unit === 'd') expiresInMs = val * 24 * 60 * 60 * 1000;
    } catch {}

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

    if (!accessToken) {
        return res.status(401).json({ message: 'Authentication required. No access token provided.' });
    }

    jwt.verify(accessToken, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Access token invalid or expired.' });
        }
        req.user = user;
        next();
    });
}

app.get('/', (req, res) => {
    res.send('🟢 Obserpoint Backend is alive!');
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    const usernameRegex = /^\w{3,20}$/;
    if (!usernameRegex.test(username)) {
        return res.status(400).json({
            message: 'Invalid username format. Username can only contain letters, numbers, and underscores (_).'
        });
    }
    
    const existing = await prisma.user.findUnique({where: {username}});
    if (existing) {
        return res.status(409).json({message: 'Username already taken.'});
    }

    const hash = await bcrypt.hash(password, 10);
    await prisma.user.create({
        data: {username, passwordHash: hash}
    });

    res.status(201).json({message: 'Registered successfully!'});
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

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Lax',
            maxAge: 15 * 60 * 1000
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({ message: 'Logged in successfully' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'An internal server error occurred during login.' });
    }
});

app.post('/refresh-token', async (req, res) => {
    const token = req.cookies.refreshToken;
    if (!token) {
        return res.status(401).json({ message: 'No refresh token provided.' });
    }

    const stored = await prisma.refreshToken.findUnique({ where: { token } });
    if (!stored || stored.expiresAt.getTime() < Date.now()) {
        await prisma.refreshToken.deleteMany({ where: { token } });
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

    res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Lax',
        maxAge: 15 * 60 * 1000
    });

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


app.post('/targets', authenticateToken, async (req, res) => {
    const {name, url, intervalSeconds} = req.body;
    if (!name || !url || !intervalSeconds) {
        return res.status(400).json({error: 'name, url and intervalSeconds are required >_<'});
    }

    const id = nextTargetId++;
    const history = [];
    const job = cron.schedule(`*/${intervalSeconds} * * * * *`, async () => {
        const start = Date.now();
        let up = false, statusCode = null;
        try {
            const r = await fetch(url);
            statusCode = r.status;
            up = r.ok;
        } catch {
            up = false;
        }
        history.unshift({
            timestamp: new Date().toISOString(),
            statusCode,
            responseTimeMs: Date.now() - start,
            up,
        });
        if (history.length > 1000) history.pop();
    }, {
        scheduled: true
    });
    job.start();
    await prisma.target.create({
        data: {name, url, intervalSeconds}
    });
    res.status(201).json({targetId: id});
});

app.get('/targets', (req, res) => {
    const list = [];
    for (const [id, t] of targets) {
        const latest = t.history[0] || {};
        list.push({
            targetId: id,
            name: t.name,
            url: t.url,
            status: latest.up === false ? 'down' : (latest.up === true ? 'up' : 'pending'),
            lastCheck: latest.timestamp || null,
            responseTimeMs: latest.responseTimeMs || null
        });
    }
    res.json(list);
});

app.get('/targets/:id/checks', (req, res) => {
    const target = targets.get(+req.params.id);
    if (!target) return res.sendStatus(404);
    res.json(target.history.slice(0, 50));
});

function setupDemoTargets() {
    console.log('Setting up demo targets...');
    const demoTargetsToCreate = [
        { name: "Google", url: "https://www.google.com", intervalSeconds: 30 },
        { name: "Youtube", url: "https://www.youtube.com", intervalSeconds: 30 },
        { name: "Twitch", url: "https://twitch.tv", intervalSeconds: 30 },
        { name: "Facebook", url: "https://www.facebook.com", intervalSeconds: 30 },
        { name: "Reeedit", url: "https://www.reeeddit.com", intervalSeconds: 30 },
        { name: "Wikipedia", url: "https://www.wikipedia.org", intervalSeconds: 30 },
        { name: "Amazon", url: "https://www.amazon.com", intervalSeconds: 30 },
        { name: "Netflix", url: "https://www.netflix.com", intervalSeconds: 30 }
    ];

    for (const targetData of demoTargetsToCreate) {
        if (Array.from(targets.values()).some(t => t.url === targetData.url)) continue;

        const id = nextTargetId++;
        const history = [];
        const job = cron.schedule(`*/${targetData.intervalSeconds} * * * * *`, async () => {
            const start = Date.now();
            let up = false, statusCode = null;
            try {
                const r = await fetch(targetData.url);
                statusCode = r.status;
                up = r.ok;
            } catch {
                up = false;
            }
            history.unshift({
                timestamp: new Date().toISOString(),
                statusCode,
                responseTimeMs: Date.now() - start,
                up,
            });
            if (history.length > 1000) history.pop();
        }, { scheduled: true });
        job.start();
        targets.set(id, { 
            name: targetData.name, 
            url: targetData.url, 
            intervalSeconds: targetData.intervalSeconds, 
            job, 
            history 
        });
        console.log(`Created demo target: ${targetData.name}`);
    }
}

app.listen(PORT, (err) => {
    if (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
    }
    console.log(`obserpoint backend listening on http://localhost:${PORT}`);
    console.log(`Frontend expected at: ${FRONTEND_URL}`);
    setupDemoTargets();
});