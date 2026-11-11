
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Joi from 'joi';
import { User } from '../models/User.js';

const COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

function setAuthCookie(res, token) {
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: COOKIE_MAX_AGE,
    path: '/',
  });
}

const registerSchema = Joi.object({
  name: Joi.string().min(2).max(60).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

// POST /api/auth/register
export async function register(req, res, next) {
  try {
    const { value, error } = registerSchema.validate(req.body);

    if (error) {
      return res.status(400).json({
        message: error.message,
      });
    }

    const existing = await User.findOne({
      email: value.email,
    });

    if (existing) {
      return res.status(409).json({
        message: 'Email already used',
      });
    }

    const password = await bcrypt.hash(value.password, 10);

    const user = await User.create({
      name: value.name,
      email: value.email,
      password,
    });

    const token = signToken(user);

    setAuthCookie(res, token);

    return res.status(201).json({
      user: publicUser(user),
    });
  } catch (error) {
    next(error);
  }
}

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

// POST /api/auth/login
export async function login(req, res, next) {
  try {
    const { value, error } = loginSchema.validate(req.body);

    if (error) {
      return res.status(400).json({
        message: error.message,
      });
    }

    const user = await User.findOne({
      email: value.email,
    });

    if (!user) {
      return res.status(401).json({
        message: 'Invalid credentials',
      });
    }

    const passwordMatches = await user.comparePassword(
      value.password
    );

    if (!passwordMatches) {
      return res.status(401).json({
        message: 'Invalid credentials',
      });
    }

    const token = signToken(user);

    setAuthCookie(res, token);

    return res.json({
      user: publicUser(user),
    });
  } catch (error) {
    next(error);
  }
}

// POST /api/auth/logout
export async function logout(req, res) {
  res.clearCookie('token', {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  });

  return res.json({
    ok: true,
  });
}

// GET /api/auth/me
export async function me(req, res, next) {
  try {
    const user = await User.findById(req.user.id).lean();

    return res.json({
      user: user ? publicUser(user) : null,
    });
  } catch (error) {
    next(error);
  }
}

function signToken(user) {
  const payload = {
    id: user._id.toString(),
    name: user.name,
  };

  return jwt.sign(
    payload,
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || '7d',
    }
  );
}

function publicUser(user) {
  return {
    id: user._id?.toString() || user.id,
    name: user.name,
    email: user.email,
  };
}
