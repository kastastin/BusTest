const router = require('express').Router();
const User = require('../models/usersModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authMiddleware = require('../middlewares/authMiddleware');

// <-- Register New User -->
router.post('/register', async (req, res) => {
  try {
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      return res.send({
        message: 'User already exists',
        success: false,
        data: null
      });
    }
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    req.body.password = hashedPassword;
    const newUser = new User(req.body);
    await newUser.save();
    res.send({
      message: 'User created successfully',
      success: true,
      data: null
    });
  } catch (error) {
    res.send({
      message: error.message,
      success: false,
      data: null
    });
  }
});

// <-- Login User -->
router.post('/login', async (req, res) => {
  try {
    const existingUser = await User.findOne({ email: req.body.email });
    if (!existingUser) {
      return res.send({
        message: 'User does not exist',
        success: false,
        data: null
      });
    }

    const passwordMatch = await bcrypt.compare(
      req.body.password,
      existingUser.password
    );

    if (!passwordMatch) {
      return res.send({
        message: 'Incorrect password',
        success: false,
        data: null
      });
    }

    if (existingUser?.isBlocked) {
      return res.send({
        success: false,
        message: 'Your account is blocked, contact admin please!',
        data: null
      });
    }

    const token = jwt.sign(
      { userId: existingUser._id },
      process.env.jwt_secret,
      { expiresIn: '1d' }
    );

    res.send({
      message: 'User logged in successfully',
      success: true,
      data: token
    });
  } catch (error) {
    res.send({
      message: error.message,
      success: false,
      data: null
    });
  }
});

// <-- Get User By Id -->
router.post('/get-user-by-id', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.body.userId);
    res.send({
      message: 'User fetched successfully',
      success: true,
      data: user
    });
  } catch (error) {
    res.send({
      message: error.message,
      success: false,
      data: null
    });
  }
});

// <-- Get All Users -->
router.post('/get-all-users', authMiddleware, async (req, res) => {
  try {
    const users = await User.find({});
    res.send({
      success: true,
      message: 'Users fetched successfully',
      data: users
    });
  } catch (error) {
    res.send({
      success: false,
      message: error.message,
      data: null
    });
  }
});

// <-- Update User -->
router.post('/update-user-permissions', authMiddleware, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.body._id, req.body);
    res.send({
      success: true,
      message: 'User permissions updated successfully',
      data: null
    });
  } catch (error) {
    res.send({
      success: false,
      message: error.message,
      data: null
    });
  }
});

module.exports = router;
