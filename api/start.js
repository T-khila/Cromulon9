import crypto from 'crypto';

function sign(payload, secret) {
    return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    try {
        const startedAt = Date.now();
        const payload = `${startedAt}`;
        const secret = process.env.SESSION_SECRET || process.env.SECRET_HASH;
        const signature = sign(payload, secret);
        const sessionId = `${startedAt}.${signature}`;
        return res.status(200).json({ sessionId, success: true });
    } catch (e) {
        return res.status(500).json({ error: 'Server error', success: false });
    }
}
