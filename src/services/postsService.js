const Cloudinary = require("../utils/cloudinary");
const postsRepository = require("../repositories/postsRepository")

class PostsService{
    static async create({
        user_id: userID, images, description
      }) {
        try {
          // Upload profile picture to Cloudify
          const imagesToInsert = [];
    
          await Promise.all(
            await images.map(async (image) => {
              const { url } = await Cloudinary.upload(image)
    
              imagesToInsert.push(url)
            })
          );
    
          const { createdPost } = await postsRepository.create(
            { userID, images: imagesToInsert, description }
          );
    
          return {
            status: true,
            error: null,
            createdPost
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
    static async getAll({ user_id: userID }) {
        try {
          const { getPosts } = await postsRepository.findAll(
            { userID }
          );
    
          return {
            status: true,
            error: null,
            getPosts
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
module.exports = PostsService;