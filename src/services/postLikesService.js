const Cloudinary = require("../utils/cloudinary");
const postLikesRepository = require("../repositories/postLikesRepository")

class PostLikesService{
  static async create({
    user_id: userID, post_id: postID
  }) {
    try {
      const { createdPostLike } = await postLikesRepository.create(
        { userID, postID }
      );

      return {
        status: true,
        error: null,
        createdPostLike
      };
    } catch (err) {
      return {
        status: false,
        error: {
          code: 500,
          message: err.message,
        },
      };
    }
  }

  static async deleteByPostID({
    user_id: userID, post_id: postID
  }) {
    try {
      const { deletedPost } = await postLikesRepository.deleteByPostID(
        { userID, postID }
      );

      return {
        status: true,
        error: null,
        deletedPost
      };
    } catch (err) {
      return {
        status: false,
        error: {
          code: 500,
          message: err.message,
        },
      };
    }
  }

    
}
module.exports = PostLikesService;