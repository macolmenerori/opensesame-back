/* eslint-disable no-unused-vars */
import { Document, Schema } from 'mongoose';

export type UserRoles = 'admin' | 'user';

export type UserType = Document & {
  id: string; // Virtual property for string representation of _id
  name: string;
  email: string;
  role: UserRoles;
  permissions: string[];
  password: string;
  passwordConfirm: string;
  passwordChangedAt?: Date;
  passwordResetToken?: string;
  passwordResetExpires?: Date;
};

export type UserSchemaType = UserType &
  Schema & {
    correctPassword: (candidatePassword: string, userPassword: string) => Promise<boolean>;
    changedPasswordAfter: (JWTTimestamp: string) => boolean;
  };
