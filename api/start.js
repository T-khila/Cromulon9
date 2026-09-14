import crypto from 'crypto';

const sessions = globalThis.__sessions || (globalThis.__sessions = new Map());

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    try {
        const sessionId = crypto.randomBytes(16).toString('hex');
        sessions.set(sessionId, { startedAt: Date.now(), used: false });
        return res.status(200).json({ sessionId, success: true });
    } catch (e) {
        return res.status(500).json({ error: 'Server error', success: false });
    }
}
