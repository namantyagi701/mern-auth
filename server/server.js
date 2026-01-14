import express from "express";
import cors from "cors";
import 'dotenv/config';
import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRoutes.js";
import userRouter from "./routes/userRouter.js";

const app = express();
const port = process.env.PORT || 4000
connectDB();

const allowedOrigins = ["http://localhost:5173", "http://localhost:5174" , "https://mern-authentication-ten-inky.vercel.app/"]
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: "https://mern-authentication-ten-inky.vercel.app", 
  credentials: true
}));

app.get('/' , (req , res) => res.send("API Working")); //test
app.use('/api/auth' , authRouter)
app.use('/api/user' , userRouter)

app.listen(port , () => console.log(`Server started on PORT:${port}`));
