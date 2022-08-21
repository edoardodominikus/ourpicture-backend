const cloudinary = require("../../config/cloudinary");

class Cloudinary {
  static async upload(data) {
    const fileBase64 = data.buffer.toString("base64");
    const file = `data:${data.mimetype};base64,${fileBase64}`;
    const cloudinaryImage = await cloudinary.uploader.upload(file);

    return cloudinaryImage;
  }
}

module.exports = Cloudinary;