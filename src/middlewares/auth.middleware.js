// auth.middleware.js
import jwt from 'jsonwebtoken';
import { pool } from "../config/db.js";

const authorize = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer')) {
            return res.status(401).json({ message: 'Unauthorized: No Bearer token' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const result = await pool.query("SELECT * FROM users WHERE id = $1", [decoded.id]);

        if (result.rows.length === 0) {
            return res.status(401).json({ message: 'Unauthorized: User not found' });
        }

        req.user = result.rows[0];
        next();
    } catch (error) {
        console.error('Authorization error:', error);
        return res.status(401).json({ message: 'Unauthorized' });
    }
};

export default authorize;
