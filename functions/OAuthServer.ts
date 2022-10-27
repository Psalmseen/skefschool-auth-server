import express from 'express';
import env from 'dotenv';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import { Secret } from 'jsonwebtoken';
import User from './models/user';
import serverless from 'serverless-http';

env.config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({ credentials: true, origin: 'http://localhost:5173' }));

app.get('/', (req, res) => {
  res.send('Welcome to SKEF school OAuth server');
});
app.post('/api/login', async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res
        .status(403)
        .json({ message: 'No user found with such username' });
    }
    const isEqual = await bcrypt.compare(password, user.password);
    if (!isEqual) {
      return res.status(403).json({ message: 'Unauthorized password' });
    }
    const refreshToken = jwt.sign(
      { userId: user._id.toString() },
      process.env.JWT_REFRESH_TOKEN_KEY as Secret
    );

    //   TODO: Implement token refresh on the front end
    //   TODO: Implement log out on the front end
    //  TODO: Move the OAuth server to its own folder and push all file to github
    //  TODO: Implement Change password
    const accessToken = jwt.sign(
      { userId: user._id.toString() },
      process.env.JWT_ACCESS_TOKEN_KEY as Secret,
      {
        expiresIn: 5 * 60,
      }
    );
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
    });
    res.cookie('accessToken', accessToken, {
      expires: new Date(new Date().getTime() + 5 * 60 * 1000),
      httpOnly: true,
    });
    user.refreshToken = refreshToken;
    await user.save();
    const {
      password: userPassword,
      refreshToken: userRefreshToken,
      ...frontendUser
    } = user.toJSON();
    res.status(200).json({ message: 'Login Successful', user: frontendUser });
  } catch (err) {
    res.status(500).json({ message: 'Failed', error: err });
  }
});

app.get('/token', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  const user = await User.findOne({ refreshToken });
  if (!user) {
    return res
      .status(403)
      .json({ message: 'You must be logged in to perform this operation' });
  }
  const { userId } = jwt.verify(
    refreshToken,
    process.env.JWT_REFRESH_TOKEN_KEY as Secret
  ) as any;

  const accessToken = jwt.sign(
    { userId },
    process.env.JWT_ACCESS_TOKEN_KEY as Secret,
    {
      expiresIn: 5 * 60,
    }
  );
  res.cookie('accessToken', accessToken, {
    expires: new Date(new Date().getTime() + 5 * 60 * 1000),
    httpOnly: true,
  });
});

app.get('/api/logout', async (req, res, next) => {
  const { refreshToken } = req.cookies;
  const user = await User.findOne({ refreshToken });
  if (!user) {
    return res
      .status(403)
      .json({ message: 'You must be logged in to perform this operation' });
  }
  user.refreshToken = '';
  user.save();
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  res.end();
});

app.post('/api/change-passowrd', async (req, res, next) => {
  const {
    cookies: { accessToken },
    body: { password },
  } = req;
  const { userId } = jwt.verify(
    accessToken,
    process.env.JWT_ACCESS_TOKEN_KEY as Secret
  ) as any;
});
let conn: any = null;
export const connect = async () => {
  if (conn === null) {
    conn = mongoose
      .connect(
        `mongodb+srv://Psalmseen:${process.env.DB_PASSWORD}@cluster0.duppj.mongodb.net/${process.env.COLLECTION}?retryWrites=true&w=majority`,
        { serverSelectionTimeoutMS: 5000 }
      )
      .then(() => mongoose);
    await conn;
  }
};
connect();

export const handler = conn ? serverless(app) : () => null;
