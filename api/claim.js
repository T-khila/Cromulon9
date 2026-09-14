export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed', success: false });
    }

    try {
        const { hash, score, mode } = req.body || {};

        if (!hash || typeof hash !== 'string') {
            return res.status(400).json({ error: 'Missing hash', success: false });
        }

        const normalized = hash.trim().toLowerCase();
        const secretHash = (process.env.SECRET_HASH || '').trim().toLowerCase();

        if (!secretHash) {
            return res.status(500).json({ error: 'Server misconfigured', success: false });
        }

        if (normalized !== secretHash) {
            return res.status(403).json({ error: 'Wrong hash', success: false });
        }

        if (mode === 'claim') {
            if (typeof score !== 'number' || score < 1000) {
                return res.status(403).json({ error: 'Score too low', success: false, score });
            }
            return res.status(200).json({ flag: process.env.FLAG, success: true });
        }

        return res.status(200).json({ success: true, mode: 'auth' });

    } catch (e) {
        return res.status(500).json({ error: 'Server error', message: e.message, success: false });
    }
}
