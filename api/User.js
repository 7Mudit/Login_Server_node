const express = require("express");
const router = express.Router();

// mongodb user model
const User = require("./../models/User");

// password handler
const bcrypt = require("bcrypt");

//signup
router.post("/signup", (req, res) => {
  let { name, email, password, dateOfBirth, phoneNumber, address } = req.body;
  name = name.trim();
  email = email.trim();
  password = password.trim();
  dateOfBirth = dateOfBirth.trim();
  phoneNumber = phoneNumber.trim();
  address = address.trim();

  if (
    name == "" ||
    email == "" ||
    password == "" ||
    dateOfBirth == "" ||
    phoneNumber == "" ||
    address == ""
  ) {
    res.json({
      status: "Failed",
      message: "Empty input fields !",
    });
  } else if (!/^[a-zA-Z ]*$/.test(name)) {
    res.json({
      status: "Falied",
      message: "Invalid name entered",
    });
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    res.json({
      status: "Failed",
      message: "Invalid email entered",
    });
  } else if (!new Date(dateOfBirth).getTime()) {
    res.json({
      status: "Failed",
      message: "Invalid date of birth entered",
    });
  } else if (password.length < 8) {
    res.json({
      status: "Failed",
      message: "Password length too short",
    });
  } else {
    // Checking if user already exists
    User.find({ email })
      .then((result) => {
        if (result.length) {
          // a user already exists
          res.json({
            status: "Failed",
            message: "User with provided email already exists",
          });
        } else {
          //try to create a new user he does not exist

          //password handling
          const saltRounds = 10;
          bcrypt
            .hash(password, saltRounds)
            .then((hashedPasword) => {
              const newUser = new User({
                name,
                email,
                password: hashedPasword,
                dateOfBirth,
                phoneNumber,
                address,
              });
              newUser
                .save()
                .then((result) => {
                  res.json({
                    status: "Success",
                    message: "Signup Successfull",
                    data: result,
                  });
                })
                .catch((err) => {
                  res.json({
                    status: "Failed",
                    message: "An error occured while saving user account",
                  });
                });
            })
            .catch((err) => {
              res.json({
                status: "Failed",
                message: "An error occured while hashing the password",
              });
            });
        }
      })
      .catch((err) => {
        console.log(err);
        res.json({
          status: "Failed",
          message: "An error occurred while checking for existing user!",
        });
      });
  }
});

// signing
router.post("/signing", (req, res) => {
  let { email, password } = req.body;
  email = email.trim();
  password = password.trim();

  if (email == "" || password == "") {
    res.json({
      status: "Failed",
      message: "Empty credentials supplied",
    });
  } else {
    //check if user exist
    User.find({ email }).then((data) => {
      if (data.length) {
        // if user exists
        const hashedPasword = data[0].password;
        bcrypt
          .compare(password, hashedPasword)
          .then((result) => {
            if (result) {
              //password match
              res.json({
                status: "Success",
                message: "Signin successfull",
                data: data,
              });
            } else {
              res.json({
                status: "Failed",
                message: "Invalid passsword entered",
              });
            }
          })
          .catch((err) => {
            res.json({
              status: "Failed",
              message: "An error occured while comparing",
            });
          });
      }
      else{
        res.json({
            status: "Failed",
            message: "Invalid credentials entered ",
        })
      }
    }).catch(err=>{
        res.json({
            status:"Failed",
            message:"An error occured while checking for existing user"
        })
    })
  }
});

module.exports = router;
