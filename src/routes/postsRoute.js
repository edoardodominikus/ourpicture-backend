const { body } = require("express-validator");
const { authenticate } = require("../middlewares/authentication");
const {
  create,
  getAll
} = require("../controllers/postsController");
const upload = require("../utils/fileUpload");

const express = require("express");
const router = express.Router();

router.post(
  "/",
  authenticate,
  body("description").isLength({ min: 5 }),
  upload.fields([{ name: "images" }]),
  create
);
router.get("/", authenticate, getAll);

module.exports = router;