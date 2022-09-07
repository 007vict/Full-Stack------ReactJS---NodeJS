import express from "express"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import mongoose from "mongoose"
import { validationResult } from "express-validator"

import { registerValidation } from "./validations/auth.js"

import UserModel from "./models/User.js"

mongoose
  .connect(
    'mongodb+srv://admin:1888@cluster0.j4ndbmk.mongodb.net/blog?retryWrites=true&w=majority',
  )
  .then(() => console.log('DB ok'))
  .catch((err) => console.log('db error', err));


const app = express()

app.use(express.json())

app.get('/',(req, res) => {
  res.send('Hello World!)!)')
})

app.post('/auth/login',async (req, res) => {
  try {
    const user = await UserModel.findOne({email: req.body.email})

    if (!user) {
      return res.status(404).json({
        message: "User not find!"
      })
    }

    const isValidPass = await bcrypt.compare(req.body.password, user._doc.passwordHash)

    if(!isValidPass) {
      return res.status(404).json({
        message: 'Password or login incorect!',
      });
    }

    const token = jwt.sign(
      {
        _id: user._id,
      },
      'secret123',
      {
        expiresIn: '30d',
      },
    );

    const { passwordHash, ...userData } = user._doc;

    return res.json({
      ...userData,
      token,
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: 'Failed to login!',
    });
  }
})

app.post('/auth/register', registerValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(errors.array());
    }

    const password = req.body.password;
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const doc = new UserModel({
      email: req.body.email,
      fullName: req.body.fullName,
      avatarUrl: req.body.avatarUrl,
      passwordHash: hash,
    });

    const user = await doc.save();

    const token = jwt.sign({
      _id: user._id
    },
    "secret123",
    {
      expiresIn: "30d",
    }
    )

    const { passwordHash, ...userData } = user._doc

    return res.json({
      ...userData,
      token
    });
  }
  catch (err) {
    console.log(err);
    res.status(500).json({
      message : "Failed to register",
    })
  }
})

app.listen(4444, (err) => {
  if (err) {
    return console.log(err);
  }

  console.log('Server OK!');
})