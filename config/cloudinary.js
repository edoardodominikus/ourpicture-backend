const cloudinary = require("cloudinary").v2

cloudinary.config({
    cloud_name: process.env.CLOUDIFY_CLOUD_NAME,
    api_key: process.env.CLOUDIFY_API_KEY,
    api_secret: process.env.CLOUDIFY_API_SECRET,
    secure: process.env.CLOUDIFY_IS_SECURE
});

module.exports = cloudinary;