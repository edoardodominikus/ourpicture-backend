const jwt = require("jsonwebtoken");

const { JWT_SECRET, JWT_EXPIRE } = process.env;

class TokenGenerator {
  static async generateJWT(user) {
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
      },
      JWT_SECRET,
      {
        expiresIn: JWT_EXPIRE,
      }
    );

    return token;
  }
}

module.exports = TokenGenerator;