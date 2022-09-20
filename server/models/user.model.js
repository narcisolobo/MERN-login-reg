const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const uniqueValidator = require('mongoose-unique-validator');

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Username is required.'],
      minLength: [4, 'Username must be at least 4 characters.'],
    },
    email: {
      type: String,
      required: [true, 'Email is required.'],
      unique: true,
      validate: {
        validator: email => /^([\w-\.]+@([\w-]+\.)+[\w-]+)?$/.test(email),
        message: 'Please enter a valid email.',
      },
    },
    password: {
      type: String,
      required: [true, 'Password is required.'],
      minlength: [8, 'Password must be 8 characters or longer.'],
    },
  },
  { timestamps: true }
);

userSchema
  .virtual('confirmPassword')
  .get(() => this._confirmPassword)
  .set(value => (this._confirmPassword = value));

userSchema.pre('validate', function (next) {
  if (this.password !== this.confirmPassword) {
    this.invalidate('confirmPassword', 'Passwords do not match.');
  }
  next();
});

userSchema.pre('save', function (next) {
  bcrypt.hash(this.password, 10).then(hash => {
    this.password = hash;
    next();
  });
});

userSchema.plugin(uniqueValidator, {
  message: 'A user with that email already exists. Please log in.',
});

const User = mongoose.model('User', userSchema);
module.exports = User;
