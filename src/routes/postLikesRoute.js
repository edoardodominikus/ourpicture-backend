const { body } = require("express-validator");
const { authenticate } = require("../middlewares/authentication");
const {
  create,
  deleteByPostID
} = require("../controllers/postLikesController");

const express = require("express");
const router = express.Router();

router.post(
  "/",
  authenticate,
  body("post_id").isNumeric(),
  create
);
router.delete("/:post_id", authenticate, deleteByPostID);

module.exports = router;