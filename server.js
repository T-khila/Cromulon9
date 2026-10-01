import express from 'express';
import crypto from 'crypto';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Разрешаем CORS (чтобы Telegram WebApp мог делать запросы)
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.status(200).end();
    next();
});

const MIN_PLAY_TIME_MS = 96 * 1000;

function sign(payload, secret) {
    return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

// --- Эндпоинт /api/start ---
app.post('/api/start', (req, res) => {
    try {
        const startedAt = Date.now();
        const payload = `${startedAt}`;
        const secret = process.env.SESSION_SECRET || process.env.SECRET_HASH;
        
        if (!secret) return res.status(500).json({ error: 'Server misconfigured', success: false });

        const signature = sign(payload, secret);
        const sessionId = `${startedAt}.${signature}`;
        return res.status(200).json({ sessionId, success: true });
    } catch (e) {
        console.error('Start error:', e);
        return res.status(500).json({ error: 'Server error', success: false });
    }
});

// --- Эндпоинт /api/claim ---
app.post('/api/claim', (req, res) => {
    try {
        const { hash, score, mode, sessionId } = req.body || {};

        if (!hash || typeof hash !== 'string') {
            return res.status(400).json({ error: 'Missing hash', success: false });
        }

        const normalized = hash.trim().toLowerCase();
        const secretHash = (process.env.SECRET_HASH || '').trim().toLowerCase();
        
        if (!secretHash) return res.status(500).json({ error: 'Server misconfigured', success: false });
        if (normalized !== secretHash) return res.status(403).json({ error: 'Wrong hash', success: false });

        if (mode === 'auth') {
            return res.status(200).json({ success: true, mode: 'auth' });
        }

        if (mode === 'claim') {
            if (typeof score !== 'number' || score < 1000) {
                return res.status(403).json({ error: 'Score too low', success: false, score });
            }

            if (!sessionId || typeof sessionId !== 'string' || !sessionId.includes('.')) {
                return res.status(403).json({ error: 'No session', success: false });
            }

            const [startedAtStr, signature] = sessionId.split('.');
            const startedAt = parseInt(startedAtStr);

            if (!startedAt || isNaN(startedAt)) return res.status(403).json({ error: 'Invalid session', success: false });

            const secret = process.env.SESSION_SECRET || process.env.SECRET_HASH;
            if (!secret) return res.status(500).json({ error: 'Server misconfigured', success: false });

            const expectedSig = sign(`${startedAt}`, secret);
            if (signature !== expectedSig) return res.status(403).json({ error: 'Invalid session', success: false });

            const elapsed = Date.now() - startedAt;
            if (elapsed < MIN_PLAY_TIME_MS) {
                return res.status(403).json({ error: 'Too fast', success: false, elapsed, required: MIN_PLAY_TIME_MS });
            }
            if (elapsed > 3600_000) return res.status(403).json({ error: 'Session expired', success: false });

            const cleanFlag = (process.env.FLAG || '').split('\n')[0].trim();
            return res.status(200).json({ flag: cleanFlag, success: true });
        }

        return res.status(400).json({ error: 'Unknown mode', success: false });
    } catch (e) {
        console.error('Claim error:', e);
        return res.status(500).json({ error: 'Server error', message: e.message, success: false });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
