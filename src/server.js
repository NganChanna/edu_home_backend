// server.js
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from "cookie-parser";
import authRouter from "./routes/auth.routes.js";
import authMiddleware from "./middlewares/auth.middleware.js";

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(cors({
    origin: [
        process.env.CLIENT_URL,
        process.env.VERCEL_URL
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
}));

const port = process.env.PORT || 3001;

app.use('/api/v1/auth',authRouter);

app.use(authMiddleware);

app.listen(port, () => {

    console.log(`Server started on http://localhost:${port}`);
})
