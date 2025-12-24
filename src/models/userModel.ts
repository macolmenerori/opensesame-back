import { compare, hash } from 'bcrypt';
import mongoose, { Schema } from 'mongoose';
import { isEmail } from 'validator';

import { UserType } from './userTypes';

const userSchema: Schema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please insert your name']
  },
  email: {
    type: String,
    required: [true, 'Please insert a valid email'],
    unique: true,
    validate: [isEmail, 'Please insert a valid email']
  },
  role: {
    type: String,
    enum: ['admin', 'user'],
    default: 'user'
  },
  permissions: {
    type: [String],
    default: []
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false // Never show the password in any output
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      // This only works on CREATE and SAVE
      validator: function (this: UserType, el: string): boolean {
        return el === this.password;
      },
      message: 'Passwords are not the same'
    }
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date
});

// Middleware to hash password before saving it to the database
userSchema.pre('save', async function () {
  if (!this.isModified('password')) {
    return;
  }
  this.password = await hash(this.password as string, 12);
  this.passwordConfirm = undefined;
  this.passwordChangedAt = Date.now() - 1000;
});

// Middleware to update the passwordChangedAt field when the password is changed
userSchema.pre('save', function () {
  if (!this.isModified('password') || this.isNew) {
    return;
  }
  this.passwordChangedAt = Date.now() - 1000; // One second less to ensure the token has been created after the password was changed
});

// Method to check if the password is correct
userSchema.methods.correctPassword = async function (
  candidatePassword: string,
  userPassword: string
): Promise<boolean> {
  return await compare(candidatePassword, userPassword); // This returns a boolean
};

// Method to check if the user changed the password after the token was issued
userSchema.methods.changedPasswordAfter = function (JWTTimestamp: string): boolean {
  const passwordChangedAt = this.passwordChangedAt as Date;
  const tokenTimestamp = parseInt(JWTTimestamp, 10);
  if (this.passwordChangedAt) {
    const changedTimestamp = passwordChangedAt.getTime() / 1000;
    return tokenTimestamp < changedTimestamp;
  }

  // False means NOT changed
  return false;
};

const User = mongoose.model<UserType>('User', userSchema);

export default User;
