import mongoose from "mongoose";

const usersSchema = new mongoose.Schema({  
  first_name: {
    type: String,
    required: true,
  },
  last_name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  isGithub: {
    type: Boolean,
    default: false,
  },
  isAdmin: {
    type: Boolean,
    required: false,
  }
});

export const usersModel = mongoose.model("Users", usersSchema);