// auth.controller.js
import { pool } from "../config/db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";


export async function registerController(req, res, next) {
    try{
        const { username , email, password } = req.body;

        const generateToken = (id) => {
            return jwt.sign({id}, process.env.JWT_SECRET, {
                expiresIn: process.env.JWT_EXPIRE,
            })
        }

        const cookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV !== 'production',
            sameSite: 'Strict',
            maxAge: 30 * 24 * 60 * 60 * 1000
        }

        if (!username || !email || !password) {
            return res.status(400).json({error: 'Username or email or password'});
        }

        const userExists = await pool.query('SELECT * FROM users WHERE email= $1', [email]);

        if (userExists.rows.length > 0) {
            return res.status(400).json({error: 'User already exists'});
        }

        const hashPassword = await bcrypt.hash(password, 10);

        const newUser = await pool.query(
            'INSERT INTO users (name, email , password) VALUES ($1, $2, $3) RETURNING id, name, email',
            [username, email, hashPassword]
        )

        const token = generateToken(newUser.rows[0].id);

        res.cookie('access_token', token, cookieOptions);
        return res.status(201).json({
            message: 'User created successfully.',
            data: {
                user: newUser.rows[0],
                token: token,
            }
        });
    }catch(err){
        next(err);
    }
}

export async function loginController(req, res, next) {
    try{
        const { email, password } = req.body;

        const result = await pool.query("SELECT * FROM users WHERE email= $1", [email]);
        const user = result.rows[0];

        if(!user) {
            return res.status(404).json({error: 'User not found'});
        }

        const isPasswordMatch = await bcrypt.compare(password, user.password);

        if(!isPasswordMatch) {
            return res.status(401).json({error: 'User does not match'});
        }

        const token = jwt.sign({id: user.id}, process.env.JWT_SECRET, {expiresIn: process.env.JWT_EXPIRE});

        res.status(200).json({
            message: 'User logged in successfully.',
            data: {
                token,
                user
            }
        });
    }catch(err){
        next(err);
    }
}
