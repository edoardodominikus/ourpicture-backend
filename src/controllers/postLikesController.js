const { validationResult } = require("express-validator");

const postLikesService = require("../services/postLikesService");

exports.create = async (req, res, next) => {
  const { post_id } = req.body;

  // Validate payload
  const errors = validationResult(req.body);

  if (!errors.isEmpty())
    return res.status(400).jsend.fail({
      code: 400,
      message: "Silakan isi semua form dengan benar",
      error_validation: errors.array(),
    });
  const createdPostLike = await postLikesService.create({
    user_id: req.user.id,
    post_id: post_id
  });

  if (!createdPostLike.status)
    return res.status(createdPostLike.error.code).jsend.fail({
      code: createdPostLike.error.code,
      message: createdPostLike.error.message,
      error_validation: createdPostLike.error_validation,
    });

  return res.jsend.success({
    code: 200,
    message: "Like Post berhasil dibuat",
    created_post_like: createdPostLike.createdPostLike,
    error_validation: [],
  });
};

exports.deleteByPostID = async (req, res, next) => {
  const { post_id } = req.params;

  const deletedPostLike = await postLikesService.deleteByPostID({
    user_id: req.user.id,
    post_id: post_id
  });

  if (!deletedPostLike.status)
    return res.status(deletedPostLike.error.code).jsend.fail({
      code: deletedPostLike.error.code,
      message: deletedPostLike.error.message,
      error_validation: deletedPostLike.error_validation,
    });

  return res.jsend.success({
    code: 200,
    message: "",
    deleted_post_like: deletedPostLike.deletedPostLike,
    error_validation: [],
  });
};