// Import required modules
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const dotenv = require("dotenv")

// Load environment variables from .env file
dotenv.config()

// Create an instance of Express app
const app = express()
const PORT = 3000

// Secret key for JWT
const secretKey = process.env.SECRET_KEY

// Dummy database for storing users and posts
const users = []
const posts = []

// Middleware to parse incoming request bodies
app.use(bodyParser.json())

// Middleware for verifying access token
function verifyToken(req, res, next) {
  const bearerHeader = req.headers["authorization"]

  if (typeof bearerHeader !== "undefined") {
    const bearerToken = bearerHeader.split(" ")[1]
    jwt.verify(bearerToken, secretKey, (err, decoded) => {
      if (err) {
        return res.sendStatus(403)
      }
      req.username = decoded.username
      next()
    })
  } else {
    res.sendStatus(403)
  }
}

// Endpoint for user registration
app.post("/api/register", (req, res) => {
  const { username, password } = req.body

  // Check if username already exists
  if (users.some(user => user.username === username)) {
    return res.status(400).json({ message: "Username already exists" })
  }

  // Create a new user object
  const newUser = { username, password }
  users.push(newUser)

  // Return success message
  res.json({ message: "User registered successfully" })
})

// Endpoint for user login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body

  // Find user by username
  const user = users.find(user => user.username === username)

  // Check if user exists and password is correct
  if (!user || user.password !== password) {
    return res.status(401).json({ message: "Invalid username or password" })
  }

  // Generate access token and refresh token
  const accessToken = jwt.sign({ username: user.username }, secretKey, {
    expiresIn: process.env.ACCESS_TOKEN_EXPIRATION,
  })
  const refreshToken = jwt.sign({ username: user.username }, secretKey, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRATION,
  })

  // Return access token and refresh token
  res.json({ accessToken, refreshToken })
})

// Endpoint for refreshing access token
app.post("/api/refresh-token", (req, res) => {
  const { refreshToken } = req.body

  // Verify the refresh token
  jwt.verify(refreshToken, secretKey, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid refresh token" })
    }

    // Generate a new access token
    const accessToken = jwt.sign({ username: decoded.username }, secretKey, {
      expiresIn: "15m",
    })

    // Return the new access token
    res.json({ accessToken })
  })
})

// Endpoint for creating a post
app.post("/api/posts", verifyToken, (req, res) => {
  const { title, message } = req.body

  // Create a new post object
  const newPost = { title, message, author: req.username }
  posts.push(newPost)

  // Return success message
  res.json({ message: "Post created successfully" })
})

// Endpoint for viewing the title and message of the post
app.get("/api/posts", verifyToken, (req, res) => {
  // Return the title and message of the latest post
  if (posts.length > 0) {
    const latestPost = posts[posts.length - 1]
    res.json({ title: latestPost.title, message: latestPost.message })
  } else {
    res.status(404).json({ message: "No posts available" })
  }
})

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`)
})

module.exports = app
