const express = require("express");
const jwt = require("jwt-simple");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const path = require("path");

// Load environment variables from .env file
dotenv.config();

// Initialize the app
const app = express();
app.use(express.json()); // Middleware to parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Middleware to parse form data

// Serve static files (HTML pages)
app.use(express.static(path.join(__dirname, "public")));

const users = []; // In-memory array to store user info (this can be replaced with a database)

// Helper function to generate JWT tokens
const generateToken = (user) => {
  const payload = { username: user.username };
  return jwt.encode(payload, process.env.JWT_SECRET);
};

// Root route to check if the server is running
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Registration route
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  // Check if the user already exists
  const existingUser = users.find((user) => user.username === username);
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  // Hash the password before saving it
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { username, password: hashedPassword };
  users.push(newUser);

  res.status(201).json({ message: "User registered successfully" });
});

// Login route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Find the user in the "database" (in this case, the `users` array)
  const user = users.find((user) => user.username === username);
  if (!user) {
    return res.status(400).json({ message: "Invalid username or password" });
  }

  // Compare the entered password with the stored hashed password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Invalid username or password" });
  }

  // Generate a JWT token and send it to the client
  const token = generateToken(user);
  res.json({ message: "Login successful", token });
});

// Protected route (only accessible with a valid token)
const authenticateJWT = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Access Denied" });
  }

  try {
    const decoded = jwt.decode(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach decoded user data to the request object
    next(); // Proceed to the next middleware or route handler
  } catch (error) {
    res.status(400).json({ message: "Invalid or expired token" });
  }
};

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
