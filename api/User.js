const express = require("express");
const router = express.Router();

// mongodb user model
const User = require("./../models/User");

// mongodb user verification model
const UserVerification = require("./../models/UserVerification");

//mongodb password verification model
const PasswordReset = require("./../models/PasswordReset");

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

//password reset stuff
router.post("/requestPasswordReset", (req, res) => {
  const { email, redirectUrl } = req.body;

  // check if email exists
  User.find({ email })
    .then((data) => {
      if (data.length) {
        //user exists

        //check if user is verified
        if (!data[0].verified) {
          res.json({
            status: "Failed",
            message: "Email has not been verified yet. Check your inbox",
          });
        } else {
          //proceed with the email to reset password
          sendResetEmail(data[0], redirectUrl, res);
        }
      } else {
        res.json({
          status: "Failed",
          message: "No account with the supplied email",
        });
      }
    })
    .catch((error) => {
      console.log(error);
      res.json({
        status: "Failed",
        message: "An error occured while checking for existing user",
      });
    });
});

//send password reset email
const sendResetEmail = ({ _id, email }, redirectUrl, res) => {
  const resetString = uuidv4() + _id;
  // First we clear all existing reset records
  PasswordReset.deleteMany({ userId: _id })
    .then((result) => {
      //reset records deleted successfully
      //now we send the email
      const mailOptions = {
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: "Password Reset",
        html: `<p>We heard that you lost the password</p><p>Don't worry,use the link below to reset it.<b>This link expires in 60 minutes</b></p><p>Press <a href=${
          redirectUrl + "/" + _id + "/" + resetString
        }>here</a>to proceed</p>`,
      };
      //hash the reset string
      const saltRounds = 10;
      bcrypt
        .hash(resetString, saltRounds)
        .then((hashedResetString) => {
          //set values in password reset collection
          const newPasswordReset = new PasswordReset({
            userId: _id,
            resetString: hashedResetString,
            createdAt: Date.now(),
            expiresAt: Date.now() + 3600000,
          });

          newPasswordReset
          .save()
          .then(()=>{
            transporter.sendMail(mailOptions)
            .then(()=>{
              //reset email sent and password reset record saved
              res.json({
                status:"Pending",
                message:"Password reset email sent"
              })
            })
            .catch(error=>{
              console.log(error)
              res.json({
                status: "Failed",
                message: "Password reset email failed",
              });
            })
          })
          .catch(error=>{
            console.log(error)
            res.json({
              status: "Failed",
              message: "Could not save the password reset data",
            });
          })
        })
        .catch((error) => {
          console.log(error);
          res.json({
            status: "Failed",
            message: "An error occured while hashing the password reset data!",
          });
        });
    })
    .catch((error) => {
      //error while clearing existign records
      console.log(error);
      res.json({
        status: "Failed",
        message: "Clearing existing password reset records failed",
      });
    });
};

// actually reset the password
router.post("/resetPassword",(req,res)=>{
  let{userId,resetString,newPassword}=req.body

  PasswordReset
  .find({userId})
  .then(result=>{
    if(result.length > 0){

      //password reset record exists so we proceed
      const {expiresAt}=result[0]
      const hashedResetString=result[0].resetString
      //checking for expired reset string
      if(expiresAt<Date.now()){
        PasswordReset.deleteOne({userId})
        .then(()=>{
          // reset record deleted successfully
          res.json({
            status: "Failed",
            message: "Password reset link has expired",
          });
        })
        .catch(error=>{
          //deletion failed
          res.json({
            status: "Failed",
            message: "Clearing password reset record failed",
          });
        })
      }
      else{
        // valid reset record exists so we validate the reset string
        //first compare the hashed reset string
        bcrypt
        .compare(resetString,hashedResetString)
        .then((result)=>{
          if(result){
            // string matched
            // hash password again
            const saltRounds=10;
            bcrypt
            .hash(newPassword,saltRounds)
            .then(hashedNewPassword=>{
              // update user password
              User.updateOne({_id:userId},{password:hashedNewPassword})
              .then(()=>{
                // update complete  now delete reset record
                PasswordReset.deleteOne({userId})
                .then(()=>{
                  //both user record and reset record updated
                  res.json({
                    status: "Success",
                    message: "Password has been reset successfully",
                  });
                })
                .catch(error=>{
                  console.log(error)
                  res.json({
                    status: "Failed",
                    message: "An error occured while finalizing password reset",
                  });
                })
              })
              .catch(error=>{
                console.log(error)
                res.json({
                  status: "Failed",
                  message: "Updating user password failed",
                });
              })
            })
            .catch(error=>{
              console.log(error)
              res.json({
                status: "Failed",
                message: "An error occured while hashing new password.",
              });
            })
          }
          else{
            //existing record but incorrect reset string passed
            res.json({
              status: "Failed",
              message: "Invalid password reset details passed",
            });
          }
        })
        .catch(error=>{
          console.log(error)
          res.json({
            status: "Failed",
            message: "Comparing password reset strings failed",
          });
        })

      }
    }
    else{
      //password reset record does not exist
      res.json({
        status: "Failed",
        message: "Password reset request not found",
      });
    }
  })
  .catch(error=>{
    console.log(error)
    res.json({
      status: "Failed",
      message: "Checking for existing password reset failed",
    });
  })
})

module.exports = router;
