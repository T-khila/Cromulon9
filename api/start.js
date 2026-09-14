import crypto from 'crypto';

const sessions = globalThis.__sessions || (globalThis.__sessions = new Map());

function verifyInitData(initData, botToken) {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) return false;
    params.delete('hash');

    const dataCheckString = [...params.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => `${k}=${v}`)
        .join('\n');

    const secretKey = crypto
        .createHmac('sha256', 'WebAppData')
        .update(botToken)
        .digest();

    const computed = crypto
        .createHmac('sha256', secretKey)
        .update(dataCheckString)
        .digest('hex');

    if (computed !== hash) return false;

    const authDate = parseInt(params.get('auth_date')) * 1000;
    if (Date.now() - authDate > 3600_000) return false;

    return true;
}

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    try {
        const { initData } = req.body || {};
        if (!initData || typeof initData !== 'string') {
            return res.status(400).json({ error: 'Missing initData', success: false });
        }

        if (!verifyInitData(initData, process.env.BOT_TOKEN)) {
            return res.status(403).json({ error: 'Invalid initData', success: false });
        }

        const sessionId = crypto.randomBytes(16).toString('hex');
        sessions.set(sessionId, { startedAt: Date.now(), used: false });

        return res.status(200).json({ sessionId, success: true });
    } catch (e) {
        return res.status(500).json({ error: 'Server error', success: false });
    }
}
