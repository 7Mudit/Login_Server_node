const express = require("express");
const router = express.Router();

// mongodb user model
const User = require("./../models/User");

// mongodb user verification model
const UserVerification = require("./../models/UserVerification");

//email handler
const nodemailer = require("nodemailer");

//unique string
const { v4: uuidv4 } = require("uuid");

// env variables
require("dotenv").config();

//path for static verified page
const path = require("path");

// nodemailer stuff
let transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASS,
  },
});

//testing success
transporter.verify((error, success) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Ready for messages");
    console.log(success);
  }
});

// password handler
const bcrypt = require("bcrypt");

//signup
router.post("/signup", (req, res) => {
  let { name, email, password, dateOfBirth, phoneNumber, address } = req.body;
  name = name.trim();
  email = email.trim();
  password = password.trim();
  dateOfBirth = dateOfBirth.trim();

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
                verified: false,
              });
              newUser
                .save()
                .then((result) => {
                  // res.json({
                  //   status: "Success",
                  //   message: "Signup Successfull",
                  //   data: result,
                  // });
                  //handle account verification
                  sendVerificationEmail(result, res);
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

//send verification mail
const sendVerificationEmail = ({ _id, email }, res) => {
  //url to be used in the email
  const currentUrl = "http://localhost:3000/";
  const uniqueString = uuidv4() + _id;
  // mail options
  const mailOptions = {
    from: process.env.AUTH_EMAIL,
    to: email,
    subject: "Verify your Email",
    html: `<p>Verify your email address to complete the signup and login into your account</p><p>This link expires in<b> 6 hours</b></p><p>Press <a href=${
      currentUrl + "user/verify/" + _id + "/" + uniqueString
    }>here</a>to proceed</p>`,
  };
  // hash the uniquestirng
  const saltRounds = 10;
  bcrypt
    .hash(uniqueString, saltRounds)
    .then((hashedUniqueString) => {
      // set values in user Verification
      const newVerification = new UserVerification({
        userId: _id,
        uniqueString: hashedUniqueString,
        createdAt: Date.now(),
        expiresAt: Date.now() + 21600000,
      });

      newVerification
        .save()
        .then(() => {
          transporter
            .sendMail(mailOptions)
            .then(() => {
              // email sent and verification record saved
              res.json({
                status: "Pending",
                message: "Verification email sent",
              });
            })
            .catch((error) => {
              res.json({
                status: "Failed",
                message: "Couldn't send email",
              });
            });
        })
        .catch((error) => {
          console.log(error);
          res.json({
            status: "Failed",
            message: "Couldn't save verification email data",
          });
        });
    })
    .catch(() => {
      res.json({
        status: "Failed",
        message: "An error occured while hashing email data!",
      });
    });
};

//verify email
router.get("/verify/:userId/:uniqueString", (req, res) => {
  let { userId, uniqueString } = req.params;

  UserVerification.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        //user verification record exists so we can proceed
        const { expiresAt } = result[0];
        const hashedUniqueString = result[0].uniqueString;
        //checking for expired unique string
        if (expiresAt < Date.now()) {
          //record has expired so we delete it
          UserVerification.deleteOne({ userId })
            .then((result) => {
              User.deleteOne({ _id: userId })
                .then(() => {
                  let message = "Link has expired. Please sign up again";
                  res.redirect(`/user/verfied/error=true&message=${message}`);
                })
                .catch((error) => {
                  let message =
                    "Clearing user with expired unique string failed";
                  res.redirect(`/user/verfied/error=true&message=${message}`);
                });
            })
            .catch((error) => {
              console.log(error);
              let message =
                "An error occured while clearing expired user verification record";
              res.redirect(`/user/verfied/error=true&message=${message}`);
            });
        } else {
          // valid record exists so we validate the user
          //first compare the hashed unique string

          bcrypt
            .compare(uniqueString, hashedUniqueString)
            .then((result) => {
              if (result) {
                //string match
                User.updateOne({ _id: userId }, { verified: true })
                  .then(() => {
                    UserVerification.deleteOne({ userId })
                      .then(() => {
                        res.sendFile(
                          path.join(__dirname, "./../views/verified.html")
                        );
                      })
                      .catch((error) => {
                        let message =
                          "An error occured while finalizing successfull";
                        res.redirect(
                          `/user/verfied/error=true&message=${message}`
                        );
                      });
                  })
                  .catch((error) => {
                    console.log(error);
                    let message =
                      "An error occured while updating user record to show verified";
                    res.redirect(`/user/verfied/error=true&message=${message}`);
                  });
              } else {
                //existing record but incorrect verification details
                let message =
                  "Invalid verification details passed Check your inbox";
                res.redirect(`/user/verfied/error=true&message=${message}`);
              }
            })
            .catch((error) => {
              let message = "An error occured while comparing unique strings";
              res.redirect(`/user/verfied/error=true&message=${message}`);
            });
        }
      } else {
        //user verifcation record does not exist
        let message =
          "Account record does not exist or has been verified already Please sign in or log in";
        res.redirect(`/user/verfied/error=true&message=${message}`);
      }
    })
    .catch((error) => {
      console.log(error);
      let message =
        "An error occured while checking for existing user verification";
      res.redirect(`/user/verfied/error=true&message=${message}`);
    });
});

//verified page route
router.get("/verified", (req, res) => {
  res.sendFile(path.join(__dirname, "./../views/verified.html"));
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
    User.find({ email })
      .then((data) => {
        if (data.length) {
          // if user exists

          //check if user is verified
          if (!data[0].verified) {
            res.json({
              status: "Failed",
              message: "Email has not been verified yet. Check your inbox",
            });
          } else {
            const hashedPasword = data[0].password;
            bcrypt
              .compare(password, hashedPasword)
              .then((result) => {
                if (result) {
                  //password match
                  res.json({
                    status: "Success",
                    message: "Signing successfull",
                    data: data,
                  });
                } else {
                  res.json({
                    status: "Failed",
                    message: "Invalid password entered",
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
        } else {
          res.json({
            status: "Failed",
            message: "Invalid credentials entered ",
          });
        }
      })
      .catch((err) => {
        res.json({
          status: "Failed",
          message: "An error occured while checking for existing user",
        });
      });
  }
});

module.exports = router;
