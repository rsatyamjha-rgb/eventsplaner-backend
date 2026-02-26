// ═══════════════════════════════════════════════
//  EventsPlaner.com – Backend Server
//  Node.js + Express + MongoDB Atlas
// ═══════════════════════════════════════════════

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const Razorpay = require('razorpay');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' })); // Production mein apna domain daalna

// ── MongoDB Connect ──
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.log('❌ MongoDB Error:', err));

// ── Razorpay Setup ──
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ═══════════════
//  MODELS
// ═══════════════

// User Schema (jo log planners dekhte hain)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: String,
  password: { type: String, required: true },
  role: { type: String, default: 'user' }, // 'user' ya 'planner' ya 'admin'
  createdAt: { type: Date, default: Date.now }
});

// Planner Schema
const plannerSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  name: { type: String, required: true },
  businessName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  city: { type: String, required: true },
  cities: [String], // Multiple cities for Pro/Premium
  eventTypes: [String],
  description: String,
  photos: [String],
  portfolio: [String],
  rating: { type: Number, default: 0 },
  totalReviews: { type: Number, default: 0 },
  plan: { type: String, enum: ['basic', 'professional', 'premium'], default: 'basic' },
  photo: String,
  subscriptionStatus: { type: String, enum: ['active', 'expired', 'pending'], default: 'pending' },
  subscriptionExpiry: Date,
  isVerified: { type: Boolean, default: false },
  isFeatured: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// Review Schema
const reviewSchema = new mongoose.Schema({
  plannerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Planner', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  userName: String,
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: String,
  eventType: String,
  createdAt: { type: Date, default: Date.now }
});

// Payment Schema
const paymentSchema = new mongoose.Schema({
  plannerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Planner' },
  razorpayOrderId: String,
  razorpayPaymentId: String,
  amount: Number,
  plan: String,
  status: { type: String, default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Planner = mongoose.model('Planner', plannerSchema);
const Review = mongoose.model('Review', reviewSchema);
const Payment = mongoose.model('Payment', paymentSchema);

// ═══════════════
//  MIDDLEWARE
// ═══════════════
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token nahi mila' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ═══════════════
//  AUTH ROUTES
// ═══════════════

// Register User
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ error: 'Email pehle se registered hai' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, phone, password: hashed });
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ message: 'Account ban gaya!', token, user: { id: user._id, name, email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Email nahi mila' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Password galat hai' });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ message: 'Login ho gaya!', token, user: { id: user._id, name: user.name, email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════
//  PLANNER ROUTES
// ═══════════════

// Get all planners (public)
app.get('/api/planners', async (req, res) => {
  try {
    const { city, eventType, search, page = 1, limit = 12 } = req.query;
    let filter = { subscriptionStatus: 'active', isActive: true };
    if (city) filter.city = city;
    if (eventType) filter.eventTypes = { $in: [eventType] };
    if (search) filter.$or = [
      { businessName: { $regex: search, $options: 'i' } },
      { name: { $regex: search, $options: 'i' } }
    ];

    const planners = await Planner.find(filter)
      .sort({ plan: -1, rating: -1 }) // premium pehle, phir rating se
      .skip((page-1)*limit)
      .limit(Number(limit));

    const total = await Planner.countDocuments(filter);
    res.json({ planners, total, pages: Math.ceil(total/limit) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get single planner
app.get('/api/planners/:id', async (req, res) => {
  try {
    const planner = await Planner.findById(req.params.id);
    if (!planner) return res.status(404).json({ error: 'Planner nahi mila' });
    const reviews = await Review.find({ plannerId: req.params.id }).sort({ createdAt: -1 });
    res.json({ planner, reviews });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Register Planner (creates order for payment)
app.post('/api/planners/register', async (req, res) => {
  try {
    const { name, businessName, email, phone, city, eventTypes, plan, password } = req.body;

    const exists = await Planner.findOne({ email });
    if (exists) return res.status(400).json({ error: 'Email pehle se registered hai' });

    // Pehle user account banao
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, phone, password: hashed, role: 'planner' });

    // Planner profile banao (pending until payment)
    const planner = await Planner.create({
      userId: user._id, name, businessName, email, phone, city,
      eventTypes: eventTypes?.split(',').map(e=>e.trim()) || [],
      plan, subscriptionStatus: 'pending'
    });

    const token = jwt.sign({ id: user._id, role: 'planner' }, process.env.JWT_SECRET, { expiresIn: '30d' });

    // Basic plan FREE hai - no payment needed
    if (plan === 'basic' || !plan) {
      await Planner.findByIdAndUpdate(planner._id, { subscriptionStatus: 'active' });
      return res.json({ message: 'Registration successful! Welcome to EventsPlaner.com', plannerId: planner._id, token, free: true });
    }

    // Pro/Premium - Razorpay order banao
    const amounts = { professional: 49900, premium: 99900 };
    const order = await razorpay.orders.create({
      amount: amounts[plan] || 49900,
      currency: 'INR',
      receipt: `planner_${planner._id}`,
      notes: { plannerId: planner._id.toString(), plan }
    });
    res.json({ order, plannerId: planner._id, token, key: process.env.RAZORPAY_KEY_ID });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Verify Razorpay Payment
app.post('/api/payment/verify', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, plannerId, plan } = req.body;

    // Signature verify karo
    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSig = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(body).digest('hex');

    if (expectedSig !== razorpay_signature) {
      return res.status(400).json({ error: 'Payment verify nahi hua' });
    }

    // Subscription activate karo
    const months = { basic: 1, professional: 1, premium: 1 };
    const expiry = new Date();
    expiry.setMonth(expiry.getMonth() + 1);

    await Planner.findByIdAndUpdate(plannerId, {
      subscriptionStatus: 'active',
      subscriptionExpiry: expiry,
      isVerified: plan !== 'basic',
      isFeatured: plan === 'premium'
    });

    await Payment.create({ plannerId, razorpayOrderId: razorpay_order_id, razorpayPaymentId: razorpay_payment_id, amount: 0, plan, status: 'success' });

    res.json({ message: 'Payment successful! Profile activate ho gaya.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════
//  REVIEW ROUTES
// ═══════════════

// Add Review
app.post('/api/reviews', authMiddleware, async (req, res) => {
  try {
    const { plannerId, rating, comment, eventType } = req.body;
    const user = await User.findById(req.user.id);

    const review = await Review.create({ plannerId, userId: req.user.id, userName: user.name, rating, comment, eventType });

    // Planner ki rating update karo
    const reviews = await Review.find({ plannerId });
    const avgRating = reviews.reduce((sum, r) => sum + r.rating, 0) / reviews.length;
    await Planner.findByIdAndUpdate(plannerId, { rating: avgRating.toFixed(1), totalReviews: reviews.length });

    res.json({ message: 'Review add ho gaya!', review });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════
//  STATS
// ═══════════════
app.get('/api/stats', async (req, res) => {
  try {
    const totalPlanners = await Planner.countDocuments({ subscriptionStatus: 'active' });
    const cities = await Planner.distinct('city');
    res.json({ totalPlanners, totalCities: cities.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════
//  ADMIN ROUTES
// ═══════════════
app.get('/api/admin/planners', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access nahi hai' });
  const planners = await Planner.find().sort({ createdAt: -1 });
  res.json(planners);
});

app.patch('/api/admin/planners/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access nahi hai' });
  const planner = await Planner.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(planner);
});

// Health check
app.get('/', (req, res) => res.json({ status: '✅ EventsPlaner.com Backend Running!' }));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
