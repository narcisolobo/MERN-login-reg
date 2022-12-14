const express = require('express');
const userRouter = express.Router();
const authenticate = require('../middleware/auth')
const {
  getAllUsers,
  register,
  login,
  logout,
  getMe,
} = require('../controllers/user.controller');

userRouter.get('/', authenticate, getAllUsers);
userRouter.post('/register', register);
userRouter.post('/login', login);
userRouter.get('/logout', logout);
userRouter.get('/me', authenticate, getMe);

module.exports = userRouter;
