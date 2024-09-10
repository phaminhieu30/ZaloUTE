const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  otp: { type: String },  // Lưu OTP tạm thời
  otpExpires: { type: Date },  // Thời gian hết hạn OTP
});

const User = mongoose.model('User', userSchema);
module.exports = User;