const { body } = require("express-validator");
const { authenticate } = require("../middlewares/authentication");
const{
    login,
    register,
    getUserCredentials,
} = require("../controllers/authController");
const upload = require("../utils/fileUpload");

const express = require("express");
const router = express.Router();

router.post(
    "/login",
    body("email").isEmail(),
    body("password").isLength({ min: 8 }),
    login
  );
router.post(
    "/register",
    body("username").isLength({ min: 5 }),
    body("name").isLength({ min: 5 }),
    body("email").isEmail(),
    body("password").isLength({ min: 8 }),
    upload.single("profile_picture"),
    register
);
router.get("/me",authenticate, getUserCredentials);
module.exports = router;