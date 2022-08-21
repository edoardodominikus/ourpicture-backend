const express = require("express");
const bodyParser = require("body-parser");
const jsend = require("jsend");
const cors = require("cors");

const app = express();
const router = express.Router();
// Get Routes
const authRoute = require("./src/routes/authRoute");
const postsRoute = require("./src/routes/postsRoute");
const postLikesRoute = require("./src/routes/postLikesRoute");

// Middlewares
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(jsend.middleware);
app.use(cors());

// Initialize Routes
router.use("/auth", authRoute);
router.use("/posts", postsRoute);
router.use("/post-likes", postLikesRoute);

app.use("/api", router);
// Run Server
const http = require('http');
const server = http.createServer(app);
const port = process.env.PORT || 8000;

server.listen(port, () => console.log(`Listening on port ${port}...`))