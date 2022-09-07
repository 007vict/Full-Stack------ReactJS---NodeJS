import mongoose from "mongoose";
import { stringify } from "querystring";

const UserSchema = mongoose.Schema({
  fullName: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  passwordHash: {
    type: String,
    required: true,
  },
  avatarUrl: String,
  },
  {
    timestamps: true,
  }
);

export default mongoose.Schema('User', UserSchema)