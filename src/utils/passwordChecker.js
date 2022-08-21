const bcrypt = require("bcrypt");

class PasswordChecker {
  static async validate(password, dbPassword) {
    const isMatch = await bcrypt.compare(password, dbPassword);

    if (!isMatch)
      return {
        status: false,
        error: {
          code: 401,
          message: "Password salah",
        },
      };
    else
      return {
        status: true,
        error: null,
      };
  }
}

module.exports = PasswordChecker;