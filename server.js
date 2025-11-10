// =======================
// Imports & Config
// =======================
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo'); // production-ready session storage
require('dotenv').config();

const emailRoutes = require('./routes/emailRoutes');

const app = express();

// =======================
// Middleware
// =======================
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

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

app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: true,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // secure cookies in prod
    sameSite: "None",
  },
}));

// =======================
// Routes
// =======================
app.use('/api/email', emailRoutes);

// Optional: simple health check route
app.get('/_health', (req, res) => res.status(200).json({ status: "OK" }));

// =======================
// Error Handling Middleware
// =======================
app.use((err, req, res, next) => {
  console.error("Error:", err.stack || err);
  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || 'Something went wrong!',
  });
});

// =======================
// Connect to MongoDB & Start Server
// =======================
const startServer = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1); // Stop server if DB connection fails
  }
};

startServer();
