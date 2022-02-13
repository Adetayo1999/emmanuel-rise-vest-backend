const { hash, compare } = require("bcrypt");
const { createAccessToken, sendAccessToken } = require("../config/tokens");
const { verify } = require("jsonwebtoken");
const db = require("../models");
const users = db.users;

exports.registerUser = async (req, res) => {
  try {
    const { firstName, lastName, email, phoneNumber, password } = req.body;
    const hashedPassword = await hash(password, 10);
    const user = await users.create({
      firstName,
      lastName,
      email,
      phoneNumber,
      password: hashedPassword,
    });
    if (!user) {
      throw new Error("Something went wrong");
    }

    res.status(201).send({
      message: "User Created!",
    });
  } catch (err) {
    if (err.message === "Validation error") {
      err.error = "Email has been taken!";
    }

    res.status(400).send({
      message: err.message,
      error: err.error || "",
    });
  }
};

exports.loginUser = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(403).send({
      message: "Invalid Request",
    });
    return;
  }
  try {
    const user = await users.findOne({ where: { email } });

    if (!user) {
      throw new Error("Invalid Email/Password");
    }

    const isPassword = await compare(password, user.password);
    if (!isPassword) throw new Error("Invalid Email/Password");

    const accessToken = createAccessToken(user);
    sendAccessToken(accessToken, res);
  } catch (err) {
    res.status(403).send({
      message: err.message,
    });
  }
};
