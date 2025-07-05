process.on('uncaughtException', console.error);
process.on('unhandledRejection', console.error);

const cron = require('node-cron');
const express = require('express');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

app.get('/', (req, res) => {
  res.send('🟢 Obserpoint is alive!');
});

let nextId = 1;
const targets = new Map();

const PORT = process.env.PORT || 4893;

app.post('/targets', (req, res) => {
    const {name, url, intervalSeconds} = req.body;
    if (!name || !url || !intervalSeconds) {
        return res.status(400).json({error: 'name, url and intervalSeconds are required >_<'});
    }

    const id = nextId++;
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
        if (history.length > 100) history.pop();
    }, {
        scheduled: true
    });
    job.start();
    targets.set(id, {name, url, intervalSeconds, job, history});
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

app.listen(PORT, (err) => {
    if (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
    }
    console.log(`obserpoint now listening on localhost:${PORT}`);
});