const { validationResult } = require("express-validator");

const postsService = require("../services/postsService");

exports.create = async (req, res, next) => {
    const { description } = req.body
  
    // Validate payload
    const errors = validationResult(req.body);
  
    if (!errors.isEmpty())
      return res.status(400).jsend.fail({
        code: 400,
        message: "Silakan isi semua form dengan benar",
        error_validation: errors.array(),
      });
  
    const createdPost = await postsService.create({
      user_id: req.user.id,
      images: req.files.images,
      description
    });
  
    if (!createdPost.status)
      return res.status(createdPost.error.code).jsend.fail({
        code: createdPost.error.code,
        message: createdPost.error.message,
        error_validation: createdPost.error_validation,
      });
  
    return res.jsend.success({
      code: 200,
      message: "Post berhasil dibuat",
      createdPost: createdPost.createdPost,
      error_validation: [],
    });
  };
  
exports.getAll = async (req, res, next) => {
    const getPosts = await postsService.getAll({
      user_id: req.user.id
    });
  
    if (!getPosts.status)
      return res.status(getPosts.error.code).jsend.fail({
        code: getPosts.error.code,
        message: getPosts.error.message,
        error_validation: getPosts.error_validation,
      });
  
    return res.jsend.success({
      code: 200,
      message: "",
      posts: getPosts.getPosts,
      error_validation: [],
    });
};