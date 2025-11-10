// =======================
// Imports & Config
// =======================
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
require('dotenv').config();

const app = express();

// =======================
// Middleware
// =======================
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// CORS configuration
const allowedOrigins = [
  "https://www.papapet.in",
  "http://localhost:3000",
  "http://localhost:3001",
  "https://papapetadmin.vercel.app",
  "https://pa-pa-pet-admin.vercel.app",
  "https://papapet-virid.vercel.app/",
  "https://papapetfrontend.onrender.com/",
  "https://papapet-kappa.vercel.app/",
];

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Session configuration
app.use(
  session({
    resave: true,
    saveUninitialized: true,
    secret: process.env.SESSION_SECRET,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "None",
    },
  })
);

// =======================
// MongoDB Connection
// =======================
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    // serverSelectionTimeoutMS: 30000, // optional: 30s timeout
  })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// =======================
// Routes
// =======================
const emailRoutes = require('./routes/emailRoutes');
app.use('/api/email', emailRoutes);

// =======================
// Error Handling Middleware
// =======================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// =======================
// Start Server
// =======================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
