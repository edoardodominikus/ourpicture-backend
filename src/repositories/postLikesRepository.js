const dbConn = require("../../config/db_connection");

class PostLikesRepository {
  static async create(
    { userID, postID }
  ) {
    const createdPostLike = await dbConn.query(
      "INSERT INTO post_likes (user_id, post_id) VALUES ($1, $2) RETURNING *",
      [
        userID, postID
      ]
    );

    return { createdPostLike: createdPostLike.rows[0] };
  }

  static async deleteByPostID(
    { userID, postID }
  ) {
    const deletedPostLike = await dbConn.query(
      "DELETE FROM post_likes WHERE user_id = $1 AND post_id = $2 RETURNING *",
      [
        userID, postID
      ]
    );

    return { deletedPostLike: deletedPostLike.rows[0] };
  }
}

module.exports = PostLikesRepository;