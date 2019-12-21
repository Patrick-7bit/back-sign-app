const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const mongoose = require("mongoose");
require("dotenv").config();
var jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { registerValidation, loginValidation } = require("./validation");
const verify = require("./VerifyToken");

const app = express();

const port = 8000;

app.use(bodyParser.json());
app.use(cors());

//we use Mongoose as a bridge between Node server and MongoDB
mongoose.connect(
  process.env.MONGODB_URI || process.env.DB_CONNECT,
  { useNewUrlParser: true },
  () => {
    console.log("connected to db");
  }
);

// we create a model to insert data in MongoDB and we specify
// properties for values to store
const User = mongoose.model("User", {
  firstName: {
    type: String,
    minlength: 6,
    trim: true,
    required: true
  },
  lastName: {
    type: String,
    minlength: 6,
    trim: true,
    required: true
  },
  email: {
    type: String,
    minlength: 6,
    trim: true,
    required: true
  },
  password: {
    type: String,
    minlength: 6,
    maxlength: 1000,
    trim: true,
    required: true
  }
});

// we create a route to sign up and we instantiate a model that is saved in the database
app.post("/signup", async (req, res) => {
  try {
    // we use @hapi/joi to validate the data
    registerValidation(req.body);
    // we check if the email is not already registered
    const isEmail = await User.findOne({ email: req.body.email });
    if (isEmail) res.status(400).send("Email already exists");
    // we use bcrypt to hash the password
    const saltRounds = 10;
    await bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
      const newUser = new User({
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email: req.body.email,
        password: hash
      });
      newUser.save();
      res.json({ message: "Created" });
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// we create a route to login
app.post("/login", async (req, res) => {
  try {
    // we use @hapi/joi to validate the data
    loginValidation(req.body);
    // we check if the user is already registered
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).send("Email is wrong");
    // we check the password with bcrypt; if it's ok the user is logged an get a token
    await bcrypt.compare(req.body.password, user.password, function(
      err,
      isMatch
    ) {
      if (!isMatch) res.status(400).send("Password doesn't match!");
      const token = jwt.sign({ _id: user._id }, process.env.SECRET_KEY);
      res.header("auth-token", token).send(token);
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// we create a private route that is reachable only if the user is logged and has a token.
// verify is a middleware function that checks if the token is valid
app.get("/private", verify, (req, res) => {
  res.json({
    Private: {
      title: "Private space",
      description: "Welcome to your private space!"
    }
  });
});

app.listen(process.env.PORT || port, () => {
  console.log("Server has started listening on port " + port);
});
