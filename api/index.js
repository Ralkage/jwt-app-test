// Import required modules
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
require("dotenv").config()

// Create an instance of Express app
const app = express()
const PORT = 3000

// Secret key for JWT
const secretKey = process.env.SECRET_KEY

// Dummy database for storing users
const users = []

// Middleware to parse incoming request bodies
app.use(bodyParser.json())

// Endpoint for user registration
app.post("/register", (req, res) => {
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
app.post("/login", (req, res) => {
  const { username, password } = req.body

  // Find user by username
  const user = users.find(user => user.username === username)

  // Check if user exists and password is correct
  if (!user || user.password !== password) {
    return res.status(401).json({ message: "Invalid username or password" })
  }

  // Generate access token
  const accessToken = jwt.sign({ username: user.username }, secretKey, {
    expiresIn: "15m",
  })

  // Generate refresh token
  const refreshToken = jwt.sign({ username: user.username }, secretKey, {
    expiresIn: "7d",
  })

  // Return access token and refresh token
  res.json({ accessToken, refreshToken })
})

// Endpoint for refreshing access token
app.post("/refresh-token", (req, res) => {
  const { refreshToken } = req.body

  // Check if refresh token is provided
  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token is required" })
  }

  // Verify the refresh token
  jwt.verify(refreshToken, secretKey, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid refresh token" })
    }

    // Generate a new access token
    const accessToken = jwt.sign({ username: decoded.username }, secretKey, {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRATION,
    })

    // Return the new access token
    res.json({ accessToken })
  })
})

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`)
})

module.exports = app
