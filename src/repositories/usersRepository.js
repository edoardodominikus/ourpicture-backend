const dbConn = require("../../config/db_connection");

class UsersRepository{
    static async create({email,username,name,profilePicture,password}){
        const createdUser =  await dbConn.query(
            "INSERT INTO users(email, username, name, profile_picture, password) VALUES ($1,$2,$3,$4,$5) RETURNING *",
            [
                email, username, name, profilePicture, password
            ]
        );
        return { createdUser: createdUser.rows[0]};
    }
    static async findByEmail({email}){
        const getUser = await dbConn.query(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );
        return { getUser: getUser.rows[0]}
    }
    static async findByUsername({username}){
        const getUser = await dbConn.query(
            "SELECT * FROM users WHERE username = $1",
            [username]
        );
        return { getUser: getUser.rows[0]}
    }
    static async findById({id}){
        const getUser = await dbConn.query(
            "SELECT * FROM users WHERE id = $1",
            [id]
        );
        return {getUser: getUser.rows[0]}
    }
}

module.exports = UsersRepository;