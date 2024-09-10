const User = require('../models/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail');

// Helper function to generate OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Register API with OTP
exports.register = async (req, res) => {
  const { email, password } = req.body;
  
  try {
    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) return res.status(400).send('User already exists');

    // Create OTP and send via email
    const otp = generateOTP();
    const otpExpires = Date.now() + 100 * 60 * 1000;  // OTP expires in 10 mins

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    user = new User({ email, password: hashedPassword, otp, otpExpires });
    await user.save();

    // Send OTP via email
    await sendEmail(email, 'Your OTP Code', `Your OTP is ${otp}`);

    res.status(200).send('OTP sent to your email');
  } catch (error) {
    res.status(500).send('Server error');
  }
};

// Verify OTP and complete registration
exports.verifyOtp = async (req, res) => {
  const { email, otp } = req.body;
  
  try {
    const user = await User.findOne({ email });

    if (!user) return res.status(400).send('User not found');
    if (user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).send('Invalid or expired OTP');
    }

    // Clear OTP after successful verification
    user.otp = null;
    user.otpExpires = null;
    await user.save();

    res.status(200).send('Registration successful');
  } catch (error) {
    res.status(500).send('Server error');
  }
};

// Login with JWT
exports.login = async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send('User not found');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send('Invalid credentials');

    if (user.otp != null) return res.status(400).send('OTP is not null. Register again.')
    // Generate JWT
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).send('Server error');
  }
};

// Forget password (send OTP)
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send('User not found');

    const otp = generateOTP();
    user.otp = otp;
    user.otpExpires = Date.now() + 100 * 60 * 1000;  // OTP expires in 10 mins
    await user.save();

    // Send OTP via email
    await sendEmail(email, 'Password Reset OTP', `Your OTP is ${otp}`);

    res.status(200).send('OTP sent to your email');
  } catch (error) {
    res.status(500).send('Server error');
  }
};

// Reset password with OTP
exports.resetPassword = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send('User not found');
    
    if (user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).send('Invalid or expired OTP');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash("123", 10);
    user.password = hashedPassword;

    // Clear OTP after successful password reset
    user.otp = null;
    user.otpExpires = null;
    await user.save();

    res.status(200).send('Password reset successful. Pass: 123');
  } catch (error) {
    res.status(500).send('Server error');
  }
};