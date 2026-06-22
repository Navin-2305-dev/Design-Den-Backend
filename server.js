// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  DESIGN DEN — Backend API Server                                         ║
// ║  Node.js + Express + MongoDB + Razorpay + Nodemailer                     ║
// ╚══════════════════════════════════════════════════════════════════════════╝
require('dotenv').config();
const express     = require('express');
const mongoose    = require('mongoose');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const cors        = require('cors');
const Razorpay    = require('razorpay');
const crypto      = require('crypto');
const nodemailer  = require('nodemailer');
const helmet      = require('helmet');             // NEW — security headers (npm i helmet)
const rateLimit   = require('express-rate-limit');  // NEW — brute-force protection (npm i express-rate-limit)

const app = express();

// ─── Trust proxy ──────────────────────────────────────────────────────────────
// NEW: required if deployed behind a reverse proxy / load balancer (Render, Railway,
// nginx, Cloudflare, etc.) so req.ip reflects the real client IP for rate limiting
// and logging instead of the proxy's IP. Harmless if you're not behind a proxy.
app.set('trust proxy', 1);

// ─── Security headers ─────────────────────────────────────────────────────────
// NEW: sets sane defaults (X-Content-Type-Options, X-Frame-Options, HSTS when on
// HTTPS, etc). CSP is disabled here because this app inlines a LOT of <script> and
// <style> — enabling Helmet's default CSP without configuring it would break the
// site. Revisit CSP later once you're ready to externalize remaining inline code.
app.use(helmet({ contentSecurityPolicy:false, crossOriginEmbedderPolicy:false }));

// ─── Middleware ───────────────────────────────────────────────────────────────
// CORS: the production frontend domain is hardcoded below as a safe default —
// this is what actually fixes "CORS error" on the live site. ALLOWED_ORIGINS
// (optional, comma-separated) lets you ADD more domains (a custom domain,
// a staging URL, etc.) without removing this default or needing to redeploy
// just to get back to a working state.
const DEFAULT_ALLOWED_ORIGINS = [
    'https://design-den-studio.vercel.app',  // production frontend (Vercel)
];
const EXTRA_ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
// FIXED: STORE_URL previously fell back to 'http://localhost:5000' — meaning
// every email (order confirmation, commission updates, pattern delivery)
// would link customers to a localhost address if this env var were ever
// unset on Render. Falls back to the real production frontend instead.
const STORE_URL = (process.env.STORE_URL || 'https://design-den-studio.vercel.app').replace(/\/+$/, '');
// Normalize away trailing slashes — "https://x.vercel.app/" and
// "https://x.vercel.app" are the same origin to a browser but NOT the same
// string, and a same-string check is exactly what was silently breaking this
// before. This single normalization is the actual fix for that class of bug.
const stripTrailingSlash = (s) => s.replace(/\/+$/, '');
const ALLOWED_ORIGINS = [...new Set([...DEFAULT_ALLOWED_ORIGINS, ...EXTRA_ALLOWED_ORIGINS].map(stripTrailingSlash))];

app.use(cors({
    origin: (origin, callback) => {
        // No Origin header at all (curl, server-to-server, same-origin requests,
        // Razorpay webhooks) — always allow; there's no browser CORS check to fail.
        if (!origin) return callback(null, true);
        // NEW: browsers send the literal string "null" as the Origin header for
        // file:// pages (e.g. opening admin.html by double-clicking it instead of
        // serving it from a dev server). This is a real, distinct value — not the
        // same as no header at all — and needs its own explicit check. Allowed
        // here since it only ever happens when testing locally from disk.
        if (origin === 'null') return callback(null, true);
        // Always allow ANY localhost/127.0.0.1 port for local development —
        // covers Vite, CRA, Live Server, or anything else regardless of port,
        // without needing to list every possible dev server port individually.
        if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return callback(null, true);
        if (ALLOWED_ORIGINS.includes(stripTrailingSlash(origin))) return callback(null, true);
        // NEW: log rejected origins so a future mismatch shows up in Render's
        // logs immediately instead of being a CORS error only visible in the
        // browser console (where it's much harder to notice/diagnose remotely).
        console.warn(`⚠️  CORS rejected request from origin: ${origin}`);
        callback(new Error('Not allowed by CORS'));
    },
    methods:['GET','POST','PUT','DELETE','PATCH','OPTIONS'],
    allowedHeaders:['Content-Type','Authorization','X-Admin-Key'],
    credentials:false,
    optionsSuccessStatus:200
}));
app.use(express.json({ limit:'10mb' }));
app.use((req,_,next)=>{ console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.path}`); next(); });

// ─── Rate limiters ────────────────────────────────────────────────────────────
// NEW: brute-force protection. Without this, /api/auth/admin-login can be hammered
// with unlimited attempts against ADMIN_KEY, and /api/auth/login can be
// credential-stuffed against your user base.
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,      // 15 minutes
    max: 10,                        // 10 attempts per IP per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { message:'Too many attempts. Please try again in a few minutes.' }
});
const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,                         // admin key guards the whole store — stricter
    standardHeaders: true,
    legacyHeaders: false,
    message: { message:'Too many attempts. Please try again in a few minutes.' }
});
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,       // 1 minute
    max: 120,                       // generous ceiling for normal browsing/admin polling
    standardHeaders: true,
    legacyHeaders: false,
    message: { message:'Too many requests. Please slow down.' }
});
app.use('/api/', apiLimiter); // baseline floor across all API routes

// ─── Root / health check ──────────────────────────────────────────────────────
// CHANGED: this backend is API-only — the frontend (design_den_complete.html)
// and admin panel (admin.html) are deployed separately on Vercel, not served
// from here. Previously this repo's server.js also tried to serve those HTML
// files directly via express.static + sendFile, using paths that pointed at
// the PARENT directory (path.join(__dirname, '..')) — that only works if the
// HTML files happen to sit one level up from server.js on whatever host runs
// it, which is a fragile assumption and breaks the moment the deploy layout
// differs. Since the real frontend is a separate Vercel deployment anyway,
// none of that serving logic is needed — this route is just a status check.
app.get('/', (_,res) => res.json({
    status: 'ok',
    message: 'Design Den API Server',
    frontend: STORE_URL // single source of truth — same value used for email links, no separate FRONTEND_URL env var to keep in sync
}));

// ─── MongoDB ──────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI, { dbName:'design_den' })
    .then(()=> console.log('✅ MongoDB connected'))
    .catch(err=>{ console.error('❌ MongoDB:', err.message); process.exit(1); });

// ═══════════════════════════════════════════════════════════════════════════════
//  SCHEMAS & MODELS
// ═══════════════════════════════════════════════════════════════════════════════

// NEW: product variants (e.g. color, weight). Design notes:
// - A product with an EMPTY variants array behaves exactly as before — top-level
//   price/stock are authoritative. This keeps every existing product, cart item,
//   and order record working unchanged.
// - When variants ARE present, each variant carries its OWN price and stock.
//   The top-level price/stock on the product become a "starting from" display
//   value only (e.g. lowest variant price) — see the pre-save hook below.
// - Each variant gets a stable `variantId` (not Mongo's _id, to keep cart/order
//   JSON simple and avoid ObjectId-in-frontend headaches) so cart items can
//   reference "this exact variant of this exact product."
const variantSchema = new mongoose.Schema({
    variantId: { type:String, required:true },              // e.g. "red-100g", stable, set once
    label:     { type:String, required:true, trim:true },   // e.g. "Sunset Red"
    type:      { type:String, default:'option', enum:['color','weight','option'] },
    swatch:    { type:String, default:'' },                 // hex color or small image URL for color swatches
    img:       { type:String, default:'' },                 // optional variant-specific photo (falls back to product img)
    price:     { type:Number, required:true, min:0 },
    stock:     { type:Number, required:true, default:0, min:0 },
    sku:       { type:String, default:'' },
    active:    { type:Boolean, default:true }                // lets you retire one variant without deleting the product
}, { _id:false });

const productSchema = new mongoose.Schema({
    name:          { type:String, required:true, trim:true },
    price:         { type:Number, required:true, min:0 }, // base/display price — see variants note above
    originalPrice: { type:Number, default:null },
    category:      { type:String, required:true, enum:['yarn','kit','hook','bundle'] },
    stock:         { type:Number, required:true, default:0, min:0 }, // ignored once variants exist — see note above
    rating:        { type:Number, default:4.8, min:1, max:5 },
    reviewCount:   { type:Number, default:0 },
    img:           { type:String, default:'' },
    images:        { type:[String], default:[] },
    desc:          { type:String, default:'' },
    badge:         { type:String, default:'', enum:['','bestseller','hot','new'] },
    tags:          { type:[String], default:[] },
    featured:      { type:Boolean, default:false },
    active:        { type:Boolean, default:true },
    lowStockAlert: { type:Number, default:10 },
    sku:           { type:String, default:'' },
    weight:        { type:String, default:'' },
    material:      { type:String, default:'' },
    variants:      { type:[variantSchema], default:[] }, // NEW
    createdAt:     { type:Date, default:Date.now },
    updatedAt:     { type:Date, default:Date.now }
});
productSchema.index({ category:1, active:1 });
productSchema.index({ name:'text', desc:'text', tags:'text' });

// NEW: keep top-level price/stock in sync as a display/back-compat convenience
// whenever variants are present — price becomes "lowest variant price" (what
// you'd show on a product grid card before the customer picks a variant), and
// stock becomes the sum across active variants (so existing low-stock/out-of-
// stock UI logic that reads p.stock keeps working without changes).
productSchema.pre('save', function(next) {
    if (this.variants && this.variants.length) {
        const activeVariants = this.variants.filter(v => v.active);
        if (activeVariants.length) {
            this.price = Math.min(...activeVariants.map(v => v.price));
            this.stock = activeVariants.reduce((sum, v) => sum + v.stock, 0);
        } else {
            this.stock = 0; // all variants deactivated
        }
    }
    next();
});

// NEW: saved addresses (multiple, labeled). Kept separate from the legacy
// `address` field above (Mixed, single) to avoid touching existing data —
// any old single address stays exactly where it was; this is purely additive.
const savedAddressSchema = new mongoose.Schema({
    addressId: { type:String, required:true },
    label:     { type:String, default:'Home' }, // e.g. "Home", "Work"
    name:      { type:String, required:true, trim:true },
    phone:     { type:String, required:true, trim:true },
    line1:     { type:String, required:true, trim:true },
    line2:     { type:String, default:'', trim:true },
    city:      { type:String, required:true, trim:true },
    state:     { type:String, required:true, trim:true },
    pin:       { type:String, required:true, trim:true },
    isDefault: { type:Boolean, default:false }
}, { _id:false });

const userSchema = new mongoose.Schema({
    name:       { type:String, required:true, trim:true, maxlength:80 },
    email:      { type:String, required:true, unique:true, lowercase:true, trim:true },
    phone:      { type:String, default:'', trim:true },
    password:   { type:String, required:true },
    city:       { type:String, default:'' },
    address:    { type:mongoose.Schema.Types.Mixed, default:{} },
    savedAddresses: { type:[savedAddressSchema], default:[] }, // NEW
    totalSpent: { type:Number, default:0 },
    orderCount: { type:Number, default:0 },
    createdAt:  { type:Date, default:Date.now }
});
userSchema.index({ email:1 });

const cartSchema = new mongoose.Schema({
    userId:    { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, unique:true },
    items:     { type:mongoose.Schema.Types.Mixed, default:[] },
    updatedAt: { type:Date, default:Date.now }
});

const wishlistSchema = new mongoose.Schema({
    userId:    { type:mongoose.Schema.Types.ObjectId, ref:'User', required:true, unique:true },
    items:     { type:mongoose.Schema.Types.Mixed, default:[] },
    updatedAt: { type:Date, default:Date.now }
});

const orderSchema = new mongoose.Schema({
    // NEW: userId is now optional — guest checkout orders have no account behind
    // them. guestEmail/guestPhone are required instead when there's no userId
    // (enforced in the route, not here, since Mongoose conditional-required
    // across two paths gets awkward — the route is the single source of truth).
    userId:      { type:mongoose.Schema.Types.ObjectId, ref:'User', default:null },
    guestEmail:  { type:String, default:'', lowercase:true, trim:true },
    guestPhone:  { type:String, default:'', trim:true },
    isGuestOrder:{ type:Boolean, default:false },
    id:          { type:String, required:true, unique:true }, // Format: DD-XXXXXXXXXX
    items:       { type:mongoose.Schema.Types.Mixed, required:true },
    total:       { type:Number, required:true },
    shipping:    { type:Number, default:0 },
    discount:    { type:Number, default:0 },
    coupon:      { type:String, default:null },
    status:      { type:String, default:'Placed', enum:['Placed','Confirmed','Processing','Shipped','Out for Delivery','Delivered','Cancelled'] },
    date:        { type:String, required:true },
    address:     { type:mongoose.Schema.Types.Mixed },
    payment:     { method:String, txnId:String, razorpayOrderId:String },
    adminNote:   { type:String, default:'' },
    deliveryDays:{ type:Number, default:2 }, // Customizable delivery days
    createdAt:   { type:Date, default:Date.now }
});
orderSchema.index({ userId:1, createdAt:-1 });
orderSchema.index({ guestEmail:1, createdAt:-1 }); // NEW — lets guests look up their orders by email
orderSchema.index({ status:1 });
orderSchema.index({ id:1 });

const couponSchema = new mongoose.Schema({
    code:      { type:String, required:true, unique:true, uppercase:true, trim:true },
    type:      { type:String, required:true, enum:['pct','flat'] },
    val:       { type:Number, required:true, min:1 },
    desc:      { type:String, default:'' },
    min:       { type:Number, default:0 },
    maxUses:   { type:Number, default:null },
    usedCount: { type:Number, default:0 },
    expires:   { type:Date, default:null },
    status:    { type:String, default:'Active', enum:['Active','Paused','Expired'] },
    createdAt: { type:Date, default:Date.now }
});

const patternSchema = new mongoose.Schema({
    name:      { type:String, required:true, trim:true },
    level:     { type:String, default:'Beginner', enum:['Beginner','Intermediate','Advanced'] },
    time:      { type:String, default:'' },
    price:     { type:Number, default:0 },
    img:       { type:String, default:'' },
    fileUrl:   { type:String, default:'' },   // uploaded file as base64
    driveUrl:  { type:String, default:'' },   // Google Drive / direct URL
    videoUrl:  { type:String, default:'' },   // YouTube / Drive / Vimeo link
    videoData: { type:String, default:'' },   // uploaded video as base64
    desc:      { type:String, default:'' },
    downloads: { type:Number, default:0 },
    status:    { type:String, default:'Published', enum:['Published','Draft'] },
    createdAt: { type:Date, default:Date.now }
});

const testiSchema = new mongoose.Schema({
    name:      { type:String, required:true, trim:true },
    loc:       { type:String, default:'' },
    rating:    { type:Number, default:5, min:1, max:5 },
    text:      { type:String, required:true },
    emoji:     { type:String, default:'🌸' },
    date:      { type:String, default:()=>new Date().toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'}) },
    status:    { type:String, default:'Pending', enum:['Published','Pending'] },
    createdAt: { type:Date, default:Date.now }
});

const gallerySchema = new mongoose.Schema({
    url:       { type:String, required:true, trim:true },
    caption:   { type:String, default:'' },
    sortOrder: { type:Number, default:0 },
    active:    { type:Boolean, default:true },
    createdAt: { type:Date, default:Date.now }
});

const commissionSchema = new mongoose.Schema({
    commissionId: { type:String, required:true, unique:true }, // e.g. "COMM-2026-XXXX"
    type:         { type:String, required:true, trim:true },
    name:         { type:String, required:true, trim:true },
    phone:        { type:String, required:true, trim:true },
    email:        { type:String, required:true, trim:true },
    desc:         { type:String, required:true, trim:true },
    budget:       { type:String, default:'' },
    attachment:   { type:String, default:'' },
    attachName:   { type:String, default:'' },
    status:       { type:String, default:'New', enum:['New','Quoted','In Progress','Completed','Cancelled'] },
    quotedPrice:  { type:Number, default:null },
    adminNote:    { type:String, default:'' },   // visible to customer
    internalNote: { type:String, default:'' },   // admin-only
    completedAt:  { type:Date, default:null },
    createdAt:    { type:Date, default:Date.now }
});
commissionSchema.index({ email:1, createdAt:-1 });
commissionSchema.index({ commissionId:1 });
commissionSchema.index({ status:1 });

const subscriberSchema = new mongoose.Schema({
    email:     { type:String, required:true, unique:true, lowercase:true, trim:true },
    createdAt: { type:Date, default:Date.now }
});

const settingsSchema = new mongoose.Schema({
    key:   { type:String, required:true, unique:true },
    value: { type:mongoose.Schema.Types.Mixed }
});

// NEW: email failures were previously only console.warn'd — invisible unless
// someone is actively watching server logs. This schema lets failed sends
// surface in the admin panel so a missed order confirmation or pattern
// delivery actually gets noticed and can be manually resent.
const emailLogSchema = new mongoose.Schema({
    to:        { type:String, required:true },
    subject:   { type:String, required:true },
    status:    { type:String, required:true, enum:['sent','failed'] },
    error:     { type:String, default:'' },
    createdAt: { type:Date, default:Date.now }
});
emailLogSchema.index({ status:1, createdAt:-1 });

const Product     = mongoose.model('Product',    productSchema);
const User        = mongoose.model('User',        userSchema);
const Cart        = mongoose.model('Cart',        cartSchema);
const Wishlist    = mongoose.model('Wishlist',    wishlistSchema);
const Order       = mongoose.model('Order',       orderSchema);
const Coupon      = mongoose.model('Coupon',      couponSchema);
const Pattern     = mongoose.model('Pattern',     patternSchema);
const Testimonial = mongoose.model('Testimonial', testiSchema);
const Gallery     = mongoose.model('Gallery',     gallerySchema);
const Commission  = mongoose.model('Commission',  commissionSchema);
const Subscriber  = mongoose.model('Subscriber',  subscriberSchema);
const Settings    = mongoose.model('Settings',    settingsSchema);
const EmailLog    = mongoose.model('EmailLog',    emailLogSchema);

// ─── Razorpay ─────────────────────────────────────────────────────────────────
const razorpay = new Razorpay({ key_id:process.env.RAZORPAY_KEY_ID||'rzp_test_placeholder', key_secret:process.env.RAZORPAY_KEY_SECRET||'placeholder' });

// ─── Email transporter ────────────────────────────────────────────────────────
let mailer = null;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    mailer = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });
    mailer.verify(err => err ? console.warn('⚠️  Email transport error:', err.message) : console.log('✅ Email ready'));
} else {
    console.warn('⚠️  EMAIL_USER / EMAIL_PASS not set — emails disabled');
}

async function sendMail(to, subject, html) {
    if (!mailer) { await EmailLog.create({ to, subject, status:'failed', error:'Mailer not configured (EMAIL_USER/EMAIL_PASS missing)' }).catch(()=>{}); return; }
    try {
        await mailer.sendMail({ from:`"Design Den 🧶" <${process.env.EMAIL_USER}>`, to, subject, html });
        console.log(`📧 Email sent to ${to}`);
        await EmailLog.create({ to, subject, status:'sent' }).catch(()=>{});
    } catch(err) {
        console.warn(`⚠️  Email to ${to} failed:`, err.message);
        await EmailLog.create({ to, subject, status:'failed', error:err.message }).catch(()=>{});
    }
}

// ─── Email templates ──────────────────────────────────────────────────────────
function emailWrap(body) {
    return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:'Helvetica Neue',Arial,sans-serif;background:#FFF6EE;margin:0;padding:24px 0">
<div style="max-width:580px;margin:0 auto;background:white;border-radius:28px;overflow:hidden;box-shadow:0 12px 48px rgba(61,26,14,0.1)">
  <div style="background:linear-gradient(135deg,#3D1A0E 0%,#8B3252 60%,#D4748C 100%);padding:48px 40px 40px;text-align:center;position:relative;">
    <div style="font-size:3rem;margin-bottom:14px;line-height:1;">🧶</div>
    <h1 style="color:white;font-size:2.2rem;margin:0 0 6px;font-weight:700;font-family:Georgia,serif;letter-spacing:-0.5px;">Design Den</h1>
    <p style="color:rgba(255,255,255,0.6);margin:0;font-size:0.65rem;font-weight:800;letter-spacing:4px;text-transform:uppercase;">CROCHET STUDIO · CHENNAI</p>
  </div>
  <div style="padding:40px">${body}</div>
  <div style="background:linear-gradient(135deg,#FAE8D0,#FFF6EE);padding:22px 40px;text-align:center;border-top:1px solid rgba(212,116,140,0.1)">
    <p style="color:rgba(61,26,14,0.55);font-size:0.75rem;margin:0 0 6px;font-weight:700;">Design Den Crochet Studio</p>
    <p style="color:rgba(61,26,14,0.35);font-size:0.7rem;margin:0;">Anna Nagar, Chennai, Tamil Nadu — 600040 · +91 98765 43210</p>
    <p style="color:rgba(61,26,14,0.28);font-size:0.66rem;margin:8px 0 0;">© 2026 Design Den. All rights reserved.</p>
  </div>
</div></body></html>`;
}

function welcomeEmail(name) {
    return emailWrap(`
    <div style="text-align:center;margin-bottom:32px;">
      <div style="display:inline-flex;align-items:center;gap:8px;background:linear-gradient(135deg,rgba(212,116,140,0.12),rgba(139,50,82,0.08));border:1.5px dashed rgba(212,116,140,0.4);border-radius:999px;padding:10px 24px;margin-bottom:28px;">
        <span style="font-size:0.8rem;">🎀</span>
        <span style="font-size:0.65rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#D4748C;">Welcome to the Family</span>
        <span style="font-size:0.8rem;">🎀</span>
      </div>
      <h1 style="font-family:Georgia,serif;font-size:2.2rem;font-weight:700;color:#3D1A0E;margin:0 0 10px;line-height:1.2;">Hi ${name}! 👋</h1>
      <p style="color:rgba(61,26,14,0.65);font-size:1rem;line-height:1.75;margin:0 0 8px;">We're so thrilled to have you join the <strong style="color:#3D1A0E;">Design Den</strong> family!</p>
      <p style="color:rgba(61,26,14,0.55);font-size:0.9rem;line-height:1.7;margin:0;">Whether you're a seasoned crafter or just picking up your first hook, you've found the right place.</p>
    </div>

    <p style="color:rgba(61,26,14,0.6);font-size:0.88rem;line-height:1.75;margin:0 0 28px;">From hand-dyed yarns and ergonomic hook sets to complete amigurumi kits and step-by-step patterns — everything you need to create something <em style="color:#8B3252;">beautiful</em> is right here.</p>

    <div style="background:linear-gradient(135deg,#FFF6EE,#FAE8D0);border:2px dashed rgba(212,116,140,0.35);border-radius:20px;padding:28px 32px;text-align:center;margin-bottom:32px;">
      <div style="font-size:0.65rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#D4748C;margin-bottom:14px;display:flex;align-items:center;justify-content:center;gap:8px;">
        <span>🎁</span> Your Welcome Gift
      </div>
      <div style="font-family:Georgia,serif;font-size:2.4rem;font-weight:700;letter-spacing:6px;color:#3D1A0E;margin-bottom:10px;">WELCOME10</div>
      <p style="font-size:0.88rem;font-weight:700;color:#3D1A0E;margin:0 0 6px;">10% off your first order — no minimum spend</p>
      <p style="font-size:0.72rem;color:rgba(61,26,14,0.45);margin:0;">Apply at checkout · Valid on any order</p>
    </div>

    <div style="text-align:center;margin-bottom:32px;">
      <a href="${STORE_URL}" style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;text-decoration:none;padding:15px 40px;border-radius:999px;font-weight:800;font-size:0.82rem;letter-spacing:2px;text-transform:uppercase;box-shadow:0 8px 24px rgba(139,50,82,0.25);">START SHOPPING ✦</a>
    </div>

    <div style="display:flex;gap:0;border-top:1px solid rgba(212,116,140,0.15);padding-top:24px;margin-top:4px;">
      <div style="flex:1;text-align:center;padding:0 12px;">
        <div style="font-size:1.6rem;margin-bottom:8px;">🎨</div>
        <div style="font-size:0.72rem;font-weight:800;color:#3D1A0E;margin-bottom:4px;">Hand-Dyed Yarns</div>
        <div style="font-size:0.66rem;color:rgba(61,26,14,0.5);">Premium &amp; vibrant</div>
      </div>
      <div style="flex:1;text-align:center;padding:0 12px;border-left:1px solid rgba(212,116,140,0.12);border-right:1px solid rgba(212,116,140,0.12);">
        <div style="font-size:1.6rem;margin-bottom:8px;">🚚</div>
        <div style="font-size:0.72rem;font-weight:800;color:#3D1A0E;margin-bottom:4px;">Free Shipping</div>
        <div style="font-size:0.66rem;color:rgba(61,26,14,0.5);">On orders over ₹999</div>
      </div>
      <div style="flex:1;text-align:center;padding:0 12px;">
        <div style="font-size:1.6rem;margin-bottom:8px;">📜</div>
        <div style="font-size:0.72rem;font-weight:800;color:#3D1A0E;margin-bottom:4px;">Free Patterns</div>
        <div style="font-size:0.66rem;color:rgba(61,26,14,0.5);">For every skill level</div>
      </div>
    </div>

    <div style="text-align:center;margin-top:28px;padding-top:20px;border-top:1px solid rgba(212,116,140,0.1);">
      <p style="font-size:0.82rem;color:rgba(61,26,14,0.55);margin:0 0 4px;">With yarn love,</p>
      <p style="font-family:Georgia,serif;font-size:1.1rem;font-weight:700;color:#D4748C;margin:0;">— The Design Den Team 🧶</p>
    </div>`);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTH MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════════════════
function auth(req, res, next) {
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ message:'Authentication required' });
    try {
        const payload = jwt.verify(h.slice(7), process.env.JWT_SECRET);
        if (payload.isAdmin) return res.status(403).json({ message:'Use user token' });
        req.user = payload; next();
    } catch { res.status(401).json({ message:'Invalid or expired token' }); }
}

// NEW: optional auth for guest-checkout-capable routes. If a valid user token
// is present, req.user is set (same as `auth`) and the route can treat the
// request as a logged-in order. If no token (or an invalid one) is present,
// req.user stays undefined and the route proceeds as a guest checkout instead
// of rejecting outright. Admin tokens are still rejected here — admins place
// orders through the storefront the same as anyone, never "as admin."
function optionalAuth(req, res, next) {
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer ')) { req.user = null; return next(); }
    try {
        const payload = jwt.verify(h.slice(7), process.env.JWT_SECRET);
        if (payload.isAdmin) return res.status(403).json({ message:'Use user token' });
        req.user = payload;
    } catch { req.user = null; } // invalid/expired token — fall through as guest rather than blocking
    next();
}

function adminAuth(req, res, next) {
    const adminKey = req.headers['x-admin-key'];
    if (adminKey && adminKey === process.env.ADMIN_KEY) return next();
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ message:'Admin authentication required' });
    try {
        const payload = jwt.verify(h.slice(7), process.env.JWT_SECRET);
        if (!payload.isAdmin) return res.status(403).json({ message:'Admin access only' });
        req.user = payload; next();
    } catch { res.status(401).json({ message:'Invalid admin token' }); }
}

// ─── DB Seed ──────────────────────────────────────────────────────────────────
async function seedDB() {
    if (await Product.countDocuments() > 0) return;
    console.log('🌱 Seeding initial data…');
    await Product.insertMany([
        { name:"Cotton Candy Dream",       price:399,  category:"yarn",   stock:34, rating:5.0, reviewCount:186, img:"https://picsum.photos/id/201/600/600", desc:"100% premium Merino wool from Tamil Nadu farms. Buttery soft, perfect for baby blankets.", badge:"bestseller", featured:true,  sku:"DD-Y-001", weight:"100g", material:"Merino Wool" },
        { name:"Rainbow Haze Variegated",  price:549,  category:"yarn",   stock:12, rating:4.8, reviewCount:94,  img:"https://picsum.photos/id/29/600/600",  desc:"Hand-dyed 100% cotton. Vibrant colour changes. Great for shawls & scarves.", badge:"hot", sku:"DD-Y-002", weight:"100g", material:"100% Cotton" },
        { name:"Bunny Hug Amigurumi Kit",  price:899,  category:"kit",    stock:8,  rating:5.0, reviewCount:212, img:"https://picsum.photos/id/160/600/600", desc:"Complete kit: yarn, safety eyes, stuffing, pattern. Make your own adorable bunny!", badge:"hot", featured:true, sku:"DD-K-001" },
        { name:"Ergonomic Hook Set (12pc)",price:699,  category:"hook",   stock:45, rating:4.9, reviewCount:301, img:"https://picsum.photos/id/180/600/600", desc:"Aluminium hooks with soft comfort grip. Perfect tension every stitch.", sku:"DD-H-001" },
        { name:"Golden Sunset Bundle",     price:1299, category:"bundle", stock:19, rating:5.0, reviewCount:78,  img:"https://picsum.photos/id/1015/600/600", desc:"4 skeins + exclusive pattern + ergonomic hook. Limited edition sunset tones.", badge:"new", featured:true, sku:"DD-B-001" },
        { name:"Cozy Cactus Kit",          price:799,  category:"kit",    stock:22, rating:4.7, reviewCount:143, img:"https://picsum.photos/id/201/600/600", desc:"Make your own rainbow cactus family. Beginner friendly, zero tools needed.", badge:"new", sku:"DD-K-002" },
        { name:"Silky Bamboo Yarn (100g)", price:449,  category:"yarn",   stock:51, rating:4.9, reviewCount:167, img:"https://picsum.photos/id/129/600/600", desc:"Sustainably sourced bamboo fibre. Lightweight with gorgeous drape.", sku:"DD-Y-003", weight:"100g", material:"Bamboo" },
        { name:"Cloud Baby Blanket Kit",   price:1599, category:"bundle", stock:6,  rating:5.0, reviewCount:89,  img:"https://picsum.photos/id/402/600/600", desc:"Everything you need for a dreamy baby blanket. Includes pattern video access.", sku:"DD-B-002", featured:true }
    ]);
    await Coupon.insertMany([
        { code:"WELCOME10", type:"pct",  val:10,  desc:"10% off your first order",             maxUses:200,  status:"Active" },
        { code:"YARN20",    type:"pct",  val:20,  desc:"20% off for yarn lovers",               maxUses:100,  status:"Active" },
        { code:"FLAT100",   type:"flat", val:100, desc:"₹100 off on orders above ₹500", min:500,maxUses:500,  status:"Active" },
        { code:"NEWSTITCH", type:"pct",  val:15,  desc:"15% off for new members",               maxUses:300,  status:"Active" },
        { code:"CHENNAI",   type:"flat", val:50,  desc:"₹50 off — local Chennai love",          maxUses:null, status:"Active" },
    ]);
    await Pattern.insertMany([
        { name:"Granny Square Classic", level:"Beginner",     time:"2 hrs", price:0,  img:"https://picsum.photos/id/70/400/300",  desc:"A timeless classic perfect for beginners. Learn the granny square technique step by step.", downloads:1240, status:"Published" },
        { name:"Bobble Stitch Cushion", level:"Intermediate", time:"4 hrs", price:49, img:"https://picsum.photos/id/96/400/300",  desc:"Create a gorgeous textured cushion with bobble stitches. Pattern includes video walkthrough.", downloads:876,  status:"Published" },
        { name:"Starfish Amigurumi",    level:"Beginner",     time:"3 hrs", price:0,  img:"https://picsum.photos/id/146/400/300", desc:"An adorable free amigurumi starfish pattern. Great for gifts!", downloads:654,  status:"Published" },
        { name:"Lacy Shawl Pattern",    level:"Advanced",     time:"8 hrs", price:99, img:"https://picsum.photos/id/167/400/300", desc:"An elegant lacy shawl with detailed charts and written instructions.", downloads:423,  status:"Published" },
    ]);
    await Testimonial.insertMany([
        { name:"Priya Menon",     loc:"Chennai",    rating:5, text:"Design Den completely transformed my crochet journey. The Cotton Candy yarn is absolutely divine — I've gifted three blankets already!", emoji:"🌸", status:"Published" },
        { name:"Lakshmi Rajan",   loc:"Coimbatore", rating:5, text:"The Amigurumi kits are insanely good. My daughter's bunny is so cute everyone thinks it's from abroad!", emoji:"🐰", status:"Published" },
        { name:"Ananya Krishnan", loc:"Bangalore",  rating:5, text:"I went from zero to crocheting my first cardigan in two months. Navin is so patient and knowledgeable!", emoji:"✨", status:"Published" },
        { name:"Meera Iyer",      loc:"Mumbai",     rating:5, text:"Fast shipping, gorgeous yarns, and the patterns are so well-written. My go-to store.", emoji:"🧶", status:"Published" },
        { name:"Divya Suresh",    loc:"Hyderabad",  rating:5, text:"The ergonomic hook set saved my wrists! Seriously life-changing for someone who crochets daily.", emoji:"💝", status:"Published" },
        { name:"Nithya Pillai",   loc:"Kochi",      rating:5, text:"The bundles are incredible value. Got the Golden Sunset set and the colours are breathtaking!", emoji:"🌅", status:"Published" },
    ]);
    await Gallery.insertMany([
        { url:"https://picsum.photos/id/1003/600/600", caption:"Granny Square Blanket",  sortOrder:1 },
        { url:"https://picsum.photos/id/1011/600/800", caption:"Rainbow Baby Set",       sortOrder:2 },
        { url:"https://picsum.photos/id/1015/600/600", caption:"Sunset Shawl",           sortOrder:3 },
        { url:"https://picsum.photos/id/1016/600/600", caption:"Bunny Amigurumi",        sortOrder:4 },
        { url:"https://picsum.photos/id/1018/600/800", caption:"Lacy Table Runner",      sortOrder:5 },
        { url:"https://picsum.photos/id/1019/600/600", caption:"Crochet Top",            sortOrder:6 },
        { url:"https://picsum.photos/id/1021/600/600", caption:"Holiday Ornaments",      sortOrder:7 },
        { url:"https://picsum.photos/id/1022/600/600", caption:"Workshop Project",       sortOrder:8 },
    ]);
    await Settings.insertMany([
        { key:'store.name',         value:'Design Den' },
        { key:'store.tagline',      value:'Handcrafted crochet from Chennai, Tamil Nadu' },
        { key:'store.address',      value:'Chennai, Tamil Nadu, India' },
        { key:'store.whatsapp',     value:'+919876543210' },
        { key:'store.instagram',    value:'@designden.in' },
        { key:'shipping.freeAbove', value:'999' },
        { key:'shipping.fee',       value:'99' },
        { key:'shipping.days',      value:'2' },
        { key:'shipping.cod',       value:'Yes' },
        { key:'pricing.tax',        value:'0' },
        { key:'marquee.items',      value:'Free shipping over ₹999\nHandmade with love in Chennai\nNew arrivals every week\n100% natural fibres\nCustom orders welcome' },
        { key:'admin.name',         value:'Admin' },
    ]);
    console.log('✅ Seed complete');
}

// ─── Health ───────────────────────────────────────────────────────────────────
app.get('/api/health', (_,res) => res.json({ status:'ok', ts:Date.now() }));

// ═══════════════════════════════════════════════════════════════════════════════
//  PUBLIC ROUTES — Storefront
// ═══════════════════════════════════════════════════════════════════════════════

// Products
app.get('/api/products', async (req, res) => {
    try {
        const { category, search, badge, featured, sort, minPrice, maxPrice, material, inStock } = req.query;
        const q = { active:true };
        if (category && category !== 'all') q.category = category;
        if (badge)    q.badge = badge;
        if (featured) q.featured = true;
        if (search) { const re = new RegExp(search.trim(),'i'); q.$or = [{ name:re },{ desc:re },{ tags:re }]; }
        // NEW: price range filter — operates on the (possibly variant-derived) top-level price
        if (minPrice || maxPrice) {
            q.price = {};
            if (minPrice) q.price.$gte = parseFloat(minPrice);
            if (maxPrice) q.price.$lte = parseFloat(maxPrice);
        }
        // NEW: material filter (cotton, wool, bamboo, etc) — comma-separated for multi-select
        if (material) {
            const materials = String(material).split(',').map(m=>m.trim()).filter(Boolean);
            if (materials.length) q.material = { $in: materials.map(m => new RegExp(`^${m}$`,'i')) };
        }
        // NEW: in-stock-only toggle
        if (inStock === 'true') q.stock = { $gt: 0 };

        let query = Product.find(q).select('-__v');
        if (sort === 'price_asc')       query = query.sort({ price:1 });
        else if (sort === 'price_desc') query = query.sort({ price:-1 });
        else if (sort === 'rating')     query = query.sort({ rating:-1 });
        else query = query.sort({ createdAt:-1 });
        res.json({ products: await query });
    } catch(err) { console.error('[GET /products]',err); res.status(500).json({ message:'Failed to fetch products' }); }
});
// NEW: distinct materials across active products, for populating the material
// filter checkboxes dynamically instead of hardcoding a list in the frontend.
// IMPORTANT: this must be registered BEFORE /api/products/:id below — Express
// matches routes in registration order, so /api/products/:id would otherwise
// intercept this request first, treating "materials" as a product ID and
// returning 404 (this exact bug existed here until caught by testing).
app.get('/api/products/materials', async (_,res) => {
    try {
        const materials = await Product.distinct('material', { active:true, material:{ $ne:'' } });
        res.json({ materials: materials.sort() });
    } catch { res.status(500).json({ message:'Failed to fetch materials' }); }
});
app.get('/api/products/:id', async (req, res) => {
    try {
        const p = await Product.findById(req.params.id).select('-__v');
        if (!p || !p.active) return res.status(404).json({ message:'Product not found' });
        res.json({ product: p });
    } catch { res.status(404).json({ message:'Product not found' }); }
});

// Patterns (public)
app.get('/api/patterns', async (_,res) => {
    try { res.json({ patterns: await Pattern.find({ status:'Published' }).sort({ createdAt:-1 }).select('-__v -fileUrl -videoData') }); }
    catch { res.status(500).json({ message:'Error' }); }
});

// FREE pattern: sends the file via email
app.post('/api/patterns/:id/download', async (req,res) => {
    try {
        const { email, name } = req.body;
        const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
        if (!email || !emailRx.test(email.trim())) return res.status(400).json({ message:'Please enter a valid email address to receive the pattern.' });
        const p = await Pattern.findById(req.params.id);
        if (!p || p.status !== 'Published') return res.status(404).json({ message:'Pattern not found' });
        if (p.price > 0) return res.status(403).json({ message:'This pattern requires payment. Use the purchase endpoint.' });
        await Pattern.findByIdAndUpdate(req.params.id, { $inc:{ downloads:1 } });
        sendPatternMail(email.trim().toLowerCase(), `Your Free Pattern: ${p.name} 📜`, patternDeliveryEmail(p, name||'Crafter', email), p.fileUrl||'', p.name+'.pdf');
        res.json({ success:true, downloads: (p.downloads||0)+1 });
    } catch(err) { console.error('[pattern/download]',err); res.status(500).json({ message:'Error' }); }
});

// PAID pattern: create Razorpay order
app.post('/api/patterns/:id/purchase-order', async (req,res) => {
    try {
        const p = await Pattern.findById(req.params.id);
        if (!p || p.status !== 'Published') return res.status(404).json({ message:'Pattern not found' });
        if (!p.price || p.price <= 0) return res.status(400).json({ message:'This pattern is free. Use the download endpoint.' });
        const { email } = req.body;
        const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
        if (!email || !emailRx.test(email.trim())) return res.status(400).json({ message:'Please enter your email address.' });
        
        // FIX: Razorpay enforces a strict 40-character maximum limit on receipts.
        const shortTimestamp = Date.now().toString(36);
        const shortPatternId = p._id.toString().slice(-6);
        const receiptStr = `PAT_${shortTimestamp}_${shortPatternId}`; // Well under 40 chars
        
        const rzpOrder = await razorpay.orders.create({
            amount: Math.round(p.price * 100),
            currency: 'INR',
            receipt: receiptStr,
            notes: { patternId: p._id.toString(), patternName: p.name, buyerEmail: email.trim().toLowerCase() }
        });
        res.json({ orderId: rzpOrder.id, amount: rzpOrder.amount, key: process.env.RAZORPAY_KEY_ID, patternName: p.name });
    } catch(err) { console.error('[pattern/purchase-order]',err); res.status(500).json({ message:'Payment order creation failed: '+err.message }); }
});

// PAID pattern: verify payment and deliver via email
app.post('/api/patterns/:id/verify-purchase', async (req,res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature, email, name } = req.body;
        const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(razorpay_order_id + '|' + razorpay_payment_id).digest('hex');
        if (expected !== razorpay_signature) return res.status(400).json({ success:false, message:'Payment verification failed. Please contact support.' });
        const p = await Pattern.findByIdAndUpdate(req.params.id, { $inc:{ downloads:1 } }, { new:true });
        if (!p) return res.status(404).json({ message:'Pattern not found' });
        sendPatternMail(email.trim().toLowerCase(), `Your Pattern: ${p.name} 📜`, patternDeliveryEmail(p, name||'Crafter', email, razorpay_payment_id), p.fileUrl||'', p.name+'.pdf');
        res.json({ success:true, downloads: p.downloads });
    } catch(err) { console.error('[pattern/verify-purchase]',err); res.status(500).json({ success:false, message:'Delivery failed: '+err.message }); }
});

function patternDeliveryEmail(p, customerName, email, txnId) {
    const isFree = !p.price || p.price === 0;
    const fileSection = (() => {
        if (p.driveUrl || p.fileUrl) {
            const url = p.driveUrl || p.fileUrl;
            if (url.startsWith('data:')) {
                return `<div style="background:#F7EDE6;border-radius:14px;padding:16px 20px;margin-bottom:16px;text-align:center;">
                  <div style="font-size:0.72rem;font-weight:800;color:#D4748C;margin-bottom:8px;">📥 Pattern File</div>
                  <p style="font-size:0.82rem;color:rgba(61,26,14,0.6);margin:0;">Your pattern file has been sent as an attachment to this email.</p>
                </div>`;
            }
            return `<div style="text-align:center;margin-bottom:20px;">
              <a href="${url}" style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;text-decoration:none;padding:14px 36px;border-radius:999px;font-weight:800;font-size:0.82rem;letter-spacing:2px;text-transform:uppercase;box-shadow:0 8px 24px rgba(139,50,82,0.25);">📥 DOWNLOAD PATTERN</a>
              <div style="font-size:0.68rem;color:rgba(61,26,14,0.35);margin-top:8px;">Click the button above to access your pattern file</div>
            </div>`;
        }
        if (p.videoUrl) {
            return `<div style="text-align:center;margin-bottom:20px;">
              <a href="${p.videoUrl}" style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;text-decoration:none;padding:14px 36px;border-radius:999px;font-weight:800;font-size:0.82rem;letter-spacing:2px;text-transform:uppercase;">🎬 WATCH TUTORIAL</a>
            </div>`;
        }
        return `<div style="background:#F7EDE6;border-radius:14px;padding:16px;text-align:center;margin-bottom:16px;"><p style="font-size:0.82rem;color:rgba(61,26,14,0.55);margin:0;">Our team will send your pattern files within 24 hours.</p></div>`;
    })();

    return emailWrap(`
    <div style="text-align:center;margin-bottom:28px;">
      <div style="font-size:3rem;margin-bottom:12px;">📜</div>
      <h2 style="font-family:Georgia,serif;font-size:1.8rem;color:#3D1A0E;margin:0 0 8px;">Hi ${customerName}! Here's Your Pattern ✦</h2>
      <p style="color:rgba(61,26,14,0.55);margin:0;font-size:0.9rem;">${isFree ? 'Enjoy your free download from Design Den!' : 'Thank you for your purchase!'}</p>
    </div>
    <div style="display:flex;gap:14px;margin-bottom:20px;background:#F7EDE6;border-radius:14px;padding:14px;align-items:center;">
      ${p.img ? `<img src="${p.img}" style="width:72px;height:72px;border-radius:10px;object-fit:cover;flex-shrink:0;" alt="${p.name}">` : ''}
      <div style="flex:1;">
        <div style="font-family:Georgia,serif;font-size:1.1rem;font-weight:700;color:#3D1A0E;">${p.name}</div>
        <div style="font-size:0.72rem;color:rgba(61,26,14,0.5);margin-top:2px;">${p.level} · ${p.time||'Self-paced'}</div>
        ${isFree ? '<div style="font-size:0.72rem;font-weight:800;color:#7DAA8A;margin-top:4px;">FREE PATTERN</div>' : `<div style="font-size:0.72rem;font-weight:800;color:#D4A04A;margin-top:4px;">₹${p.price} — PURCHASED ✓</div>`}
      </div>
    </div>
    ${fileSection}
    ${txnId ? `<div style="font-size:0.68rem;color:rgba(61,26,14,0.3);text-align:center;margin-bottom:16px;">Transaction ID: ${txnId}</div>` : ''}
    <div style="background:white;border:1.5px dashed rgba(212,116,140,0.3);border-radius:14px;padding:16px 20px;margin-bottom:20px;">
      <div style="font-size:0.72rem;font-weight:800;color:rgba(61,26,14,0.45);margin-bottom:8px;">Pattern Description</div>
      <div style="font-size:0.82rem;color:rgba(61,26,14,0.65);line-height:1.65;">${p.desc||'Happy stitching!'}</div>
    </div>
    <div style="text-align:center;margin-top:20px;">
      <p style="font-size:0.82rem;color:rgba(61,26,14,0.55);margin:0 0 4px;">Happy crocheting!</p>
      <p style="font-family:Georgia,serif;font-size:1.1rem;font-weight:700;color:#D4748C;margin:0;">— The Design Den Team 🧶</p>
    </div>`);
}

async function sendPatternMail(to, subject, html, fileData, fileName) {
    if (!mailer) { await EmailLog.create({ to, subject, status:'failed', error:'Mailer not configured (EMAIL_USER/EMAIL_PASS missing)' }).catch(()=>{}); return; }
    try {
        const mailOpts = { from:`"Design Den 🧶" <${process.env.EMAIL_USER}>`, to, subject, html };
        if (fileData && fileData.startsWith('data:')) {
            const matches = fileData.match(/^data:([^;]+);base64,(.+)$/);
            if (matches) {
                mailOpts.attachments = [{ filename: fileName||'pattern.pdf', content: matches[2], encoding: 'base64', contentType: matches[1] }];
            }
        }
        await mailer.sendMail(mailOpts);
        console.log(`📧 Pattern email sent to ${to}`);
        await EmailLog.create({ to, subject, status:'sent' }).catch(()=>{});
    } catch(err) {
        console.warn(`⚠️  Pattern email to ${to} failed:`, err.message);
        await EmailLog.create({ to, subject, status:'failed', error:err.message }).catch(()=>{});
    }
}

// Testimonials (public)
app.get('/api/testimonials', async (_,res) => {
    try { res.json({ testimonials: await Testimonial.find({ status:'Published' }).sort({ createdAt:-1 }).select('-__v') }); }
    catch { res.status(500).json({ message:'Error' }); }
});
app.post('/api/testimonials', async (req,res) => {
    try {
        const { name, loc, text, rating } = req.body;
        if (!name || !name.trim()) return res.status(400).json({ message:'Name is required' });
        if (!text || text.trim().length < 10) return res.status(400).json({ message:'Review must be at least 10 characters' });
        const emojis = ['🌸','🐰','✨','🧶','💝','🌅','🎀','🌺','⭐','🦋'];
        const emoji = emojis[Math.floor(Math.random()*emojis.length)];
        await Testimonial.create({ name:name.trim(), loc:(loc||'').trim(), text:text.trim(), rating:Math.min(5,Math.max(1,parseInt(rating)||5)), emoji, status:'Pending' });
        res.status(201).json({ success:true });
    } catch(err) { console.error('[POST /testimonials]',err); res.status(500).json({ message:'Submission failed' }); }
});

// Gallery (public)
app.get('/api/gallery', async (_,res) => {
    try { res.json({ images: await Gallery.find({ active:true }).sort({ sortOrder:1, createdAt:1 }).select('-__v') }); }
    catch { res.status(500).json({ message:'Error' }); }
});

// Commission submit (public)
app.post('/api/commissions', async (req,res) => {
    try {
        const { type, name, phone, email, desc, budget, attachment, attachName } = req.body;
        const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
        const phoneRx = /^[6-9]\d{9}$/;
        const cleanPhone = (v='') => v.replace(/\D/g,'').replace(/^0+/,'').replace(/^91/,'');
        if (!name || name.trim().length < 2)            return res.status(400).json({ message:'Name must be at least 2 characters' });
        if (!phone || !phoneRx.test(cleanPhone(phone))) return res.status(400).json({ message:'Enter a valid 10-digit Indian mobile number' });
        if (!email || !emailRx.test(email.trim().toLowerCase())) return res.status(400).json({ message:'Enter a valid email address' });
        if (!desc || desc.trim().length < 10)           return res.status(400).json({ message:'Please describe your project (at least 10 characters)' });

        // NEW: validate the attachment before storing it. Previously any base64
        // string was accepted as-is and written straight into MongoDB — no MIME
        // check, no size cap beyond the global 10mb JSON body limit. A few large
        // submissions could bloat the database fast, and an unvalidated MIME type
        // could be misleading if ever rendered/served back out.
        if (attachment) {
            const ALLOWED_MIME = ['image/jpeg','image/png','image/webp','image/gif','application/pdf'];
            const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024; // 5MB — generous for a reference photo or PDF
            const match = /^data:([^;]+);base64,(.+)$/.exec(attachment);
            if (!match) return res.status(400).json({ message:'Attachment must be a valid file upload.' });
            const [, mime, b64] = match;
            if (!ALLOWED_MIME.includes(mime)) return res.status(400).json({ message:'Attachment must be an image (JPG/PNG/WEBP/GIF) or PDF.' });
            const approxBytes = Math.ceil(b64.length * 3 / 4);
            if (approxBytes > MAX_ATTACHMENT_BYTES) return res.status(400).json({ message:'Attachment is too large — please keep it under 5MB.' });
        }

        const datePart = new Date().toISOString().slice(0,10).replace(/-/g,'');
        const randPart  = Math.random().toString(36).substring(2,6).toUpperCase();
        const commissionId = `COMM-${datePart}-${randPart}`;
        const commission = await Commission.create({
            commissionId,
            type:(type||'Custom Design').trim(), name:name.trim(),
            phone:cleanPhone(phone), email:email.toLowerCase().trim(),
            desc:desc.trim(), budget:(budget||'').trim(),
            attachment:attachment||'', attachName:attachName||'', status:'New'
        });
        sendMail(commission.email, `Commission Received — ${commissionId} 🎨`, commissionConfirmEmail(commission));
        res.status(201).json({ success:true, commissionId });
    } catch(err) { console.error('[POST /commissions]',err); res.status(500).json({ message:'Submission failed' }); }
});

app.get('/api/commissions/track/:commissionId', async (req,res) => {
    try {
        const c = await Commission.findOne({ commissionId: req.params.commissionId.toUpperCase() })
            .select('commissionId type name status adminNote quotedPrice createdAt budget completedAt');
        if (!c) return res.status(404).json({ message:'Commission not found. Please check your ID.' });
        res.json({ commission: c });
    } catch { res.status(500).json({ message:'Error' }); }
});

app.post('/api/commissions/track', async (req,res) => {
    try {
        const { email } = req.body;
        const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
        if (!email || !emailRx.test(email.trim().toLowerCase())) return res.status(400).json({ message:'Enter a valid email address' });
        const commissions = await Commission.find({ email:email.toLowerCase().trim() })
            .sort({ createdAt:-1 })
            .select('commissionId type name status adminNote quotedPrice createdAt budget completedAt');
        res.json({ commissions });
    } catch { res.status(500).json({ message:'Error' }); }
});

app.get('/api/user/commissions', auth, async (req,res) => {
    try {
        const user = await User.findById(req.user.id).select('email');
        if (!user) return res.status(404).json({ message:'User not found' });
        const commissions = await Commission.find({ email: user.email })
            .sort({ createdAt:-1 })
            .select('commissionId type name status adminNote quotedPrice createdAt budget completedAt');
        res.json({ commissions });
    } catch { res.status(500).json({ message:'Error' }); }
});

// ── Saved addresses ───────────────────────────────────────────────────────────
// NEW: lets returning customers save 2-3 addresses and pick one at checkout
// instead of retyping every time. CRUD scoped to the logged-in user only.
app.get('/api/user/addresses', auth, async (req,res) => {
    try {
        const user = await User.findById(req.user.id).select('savedAddresses');
        if (!user) return res.status(404).json({ message:'User not found' });
        res.json({ addresses: user.savedAddresses || [] });
    } catch { res.status(500).json({ message:'Failed to fetch addresses' }); }
});

app.post('/api/user/addresses', auth, async (req,res) => {
    try {
        const { label, name, phone, line1, line2, city, state, pin, isDefault } = req.body;
        if (!name || !phone || !line1 || !city || !state || !pin) {
            return res.status(400).json({ message:'Name, phone, address line, city, state, and pincode are all required.' });
        }
        const pinRx = /^\d{6}$/;
        if (!pinRx.test(String(pin).trim())) return res.status(400).json({ message:'Pincode must be exactly 6 digits.' });

        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message:'User not found' });

        // Cap saved addresses at a sane number — this is a convenience feature,
        // not an address book product. Oldest gets the cap; if the customer
        // truly needs more than this, they're an edge case worth talking to.
        if (user.savedAddresses.length >= 10) {
            return res.status(400).json({ message:'You can save up to 10 addresses. Please delete one before adding another.' });
        }

        const newAddr = {
            addressId: `addr-${Date.now().toString(36)}${Math.random().toString(36).slice(2,6)}`,
            label: (label||'Home').trim(), name: name.trim(), phone: phone.trim(),
            line1: line1.trim(), line2: (line2||'').trim(), city: city.trim(),
            state: state.trim(), pin: String(pin).trim(),
            isDefault: !!isDefault
        };
        // Only one address can be default — unset any existing default if this one claims it
        if (newAddr.isDefault) user.savedAddresses.forEach(a => a.isDefault = false);
        // If this is the very first address being saved, make it default automatically
        if (!user.savedAddresses.length) newAddr.isDefault = true;

        user.savedAddresses.push(newAddr);
        await user.save();
        res.status(201).json({ addresses: user.savedAddresses });
    } catch(e) { res.status(400).json({ message:e.message || 'Failed to save address' }); }
});

app.put('/api/user/addresses/:addressId', auth, async (req,res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message:'User not found' });
        const addr = user.savedAddresses.find(a => a.addressId === req.params.addressId);
        if (!addr) return res.status(404).json({ message:'Address not found' });

        const { label, name, phone, line1, line2, city, state, pin, isDefault } = req.body;
        if (pin && !/^\d{6}$/.test(String(pin).trim())) return res.status(400).json({ message:'Pincode must be exactly 6 digits.' });

        if (label!==undefined) addr.label = label.trim();
        if (name!==undefined)  addr.name  = name.trim();
        if (phone!==undefined) addr.phone = phone.trim();
        if (line1!==undefined) addr.line1 = line1.trim();
        if (line2!==undefined) addr.line2 = line2.trim();
        if (city!==undefined)  addr.city  = city.trim();
        if (state!==undefined) addr.state = state.trim();
        if (pin!==undefined)   addr.pin   = String(pin).trim();
        if (isDefault) user.savedAddresses.forEach(a => a.isDefault = a.addressId === addr.addressId);

        await user.save();
        res.json({ addresses: user.savedAddresses });
    } catch(e) { res.status(400).json({ message:e.message || 'Failed to update address' }); }
});

app.delete('/api/user/addresses/:addressId', auth, async (req,res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message:'User not found' });
        const wasDefault = user.savedAddresses.find(a => a.addressId === req.params.addressId)?.isDefault;
        user.savedAddresses = user.savedAddresses.filter(a => a.addressId !== req.params.addressId);
        // If the deleted address was the default and others remain, promote the first one
        if (wasDefault && user.savedAddresses.length) user.savedAddresses[0].isDefault = true;
        await user.save();
        res.json({ addresses: user.savedAddresses });
    } catch { res.status(500).json({ message:'Failed to delete address' }); }
});

function commissionConfirmEmail(c) {
    const typeIcon = c.type==='Custom Pattern Only'?'📐':c.type==='Fully Crocheted Piece'?'🧸':c.type==='1-on-1 Workshop'?'📅':'✦';
    return emailWrap(`
    <div style="text-align:center;margin-bottom:28px;">
      <div style="font-size:3rem;margin-bottom:12px;">${typeIcon}</div>
      <h2 style="font-family:Georgia,serif;font-size:1.8rem;color:#3D1A0E;margin:0 0 8px;">Commission Received!</h2>
      <p style="color:rgba(61,26,14,0.55);margin:0;font-size:0.9rem;">We'll get back to you within <strong style="color:#D4748C;">24 hours</strong> to discuss pricing and timeline.</p>
    </div>
    <div style="background:#F7EDE6;border-radius:16px;padding:20px 24px;margin-bottom:20px;">
      <div style="font-size:0.6rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#D4748C;margin-bottom:6px;">Your Commission ID</div>
      <div style="font-family:Georgia,serif;font-size:1.6rem;font-weight:700;color:#3D1A0E;letter-spacing:2px;">${c.commissionId}</div>
      <div style="font-size:0.72rem;color:rgba(61,26,14,0.4);margin-top:4px;">Save this ID to track your commission status anytime</div>
    </div>
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px;">
      <tr><td style="padding:8px 0;border-bottom:1px solid rgba(212,116,140,0.12);font-size:0.75rem;font-weight:700;color:rgba(61,26,14,0.45);width:120px;">Commission Type</td><td style="padding:8px 0;border-bottom:1px solid rgba(212,116,140,0.12);font-size:0.82rem;color:#3D1A0E;">${c.type}</td></tr>
      <tr><td style="padding:8px 0;border-bottom:1px solid rgba(212,116,140,0.12);font-size:0.75rem;font-weight:700;color:rgba(61,26,14,0.45);">Name</td><td style="padding:8px 0;border-bottom:1px solid rgba(212,116,140,0.12);font-size:0.82rem;color:#3D1A0E;">${c.name}</td></tr>
      ${c.budget?`<tr><td style="padding:8px 0;font-size:0.75rem;font-weight:700;color:rgba(61,26,14,0.45);">Budget Range</td><td style="padding:8px 0;font-size:0.82rem;color:#3D1A0E;">${c.budget}</td></tr>`:''}
    </table>
    <div style="background:white;border:1.5px dashed rgba(212,116,140,0.3);border-radius:14px;padding:16px 20px;margin-bottom:24px;">
      <div style="font-size:0.72rem;font-weight:700;color:rgba(61,26,14,0.45);margin-bottom:8px;">Your Project Description</div>
      <div style="font-size:0.85rem;color:rgba(61,26,14,0.7);line-height:1.65;">${c.desc.replace(/\n/g,'<br>')}</div>
    </div>
    <div style="background:linear-gradient(135deg,rgba(212,116,140,0.08),rgba(139,50,82,0.05));border-radius:14px;padding:16px 20px;text-align:center;">
      <div style="font-size:0.72rem;font-weight:800;color:#D4748C;margin-bottom:8px;">Track your commission anytime at</div>
      <a href="${STORE_URL}/#custom" style="font-weight:700;color:#8B3252;font-size:0.88rem;">${STORE_URL}</a>
      <div style="font-size:0.72rem;color:rgba(61,26,14,0.4);margin-top:4px;">Using your Commission ID: <strong>${c.commissionId}</strong></div>
    </div>
    <div style="text-align:center;margin-top:24px;padding-top:20px;border-top:1px solid rgba(212,116,140,0.1);">
      <p style="font-size:0.82rem;color:rgba(61,26,14,0.55);margin:0 0 4px;">With yarn love,</p>
      <p style="font-family:Georgia,serif;font-size:1.1rem;font-weight:700;color:#D4748C;margin:0;">— The Design Den Team 🧶</p>
    </div>`);
}

function commissionStatusEmail(c) {
    const statusMsg = {
        'Quoted':      { icon:'💰', title:'Your Quote is Ready!',     msg:`We've reviewed your project and prepared a quote for you.` },
        'In Progress': { icon:'🔨', title:'Work Has Begun!',          msg:'Great news — our team has started working on your commission!' },
        'Completed':   { icon:'🎉', title:'Your Commission is Ready!', msg:'Your custom piece is complete! We\'ll be in touch shortly.' },
        'Cancelled':   { icon:'❌', title:'Commission Cancelled',       msg:'Your commission has been cancelled.' },
    };
    const info = statusMsg[c.status] || { icon:'🔔', title:'Commission Update', msg:'Your commission status has been updated.' };
    return emailWrap(`
    <div style="text-align:center;margin-bottom:28px;">
      <div style="font-size:3rem;margin-bottom:12px;">${info.icon}</div>
      <h2 style="font-family:Georgia,serif;font-size:1.8rem;color:#3D1A0E;margin:0 0 8px;">${info.title}</h2>
      <p style="color:rgba(61,26,14,0.55);margin:0;font-size:0.9rem;">${info.msg}</p>
    </div>
    <div style="background:#F7EDE6;border-radius:16px;padding:20px 24px;margin-bottom:20px;">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;">
        <div><div style="font-size:0.6rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#D4748C;margin-bottom:4px;">Commission ID</div><div style="font-family:Georgia,serif;font-size:1.3rem;font-weight:700;color:#3D1A0E;">${c.commissionId}</div></div>
        <div style="background:linear-gradient(135deg,#D4748C,#8B3252);color:white;border-radius:99px;padding:8px 18px;font-size:0.72rem;font-weight:800;letter-spacing:1px;">${c.status.toUpperCase()}</div>
      </div>
    </div>
    ${c.quotedPrice?`<div style="background:white;border:2px dashed rgba(212,160,74,0.4);border-radius:14px;padding:16px 20px;margin-bottom:20px;text-align:center;"><div style="font-size:0.72rem;font-weight:800;color:rgba(61,26,14,0.45);margin-bottom:6px;">Quoted Price</div><div style="font-family:Georgia,serif;font-size:2rem;font-weight:700;color:#3D1A0E;">₹${c.quotedPrice.toLocaleString('en-IN')}</div></div>`:''}
    ${c.adminNote?`<div style="background:white;border-left:3px solid #D4748C;border-radius:0 14px 14px 0;padding:16px 20px;margin-bottom:20px;"><div style="font-size:0.6rem;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#D4748C;margin-bottom:8px;">📌 Message from Design Den</div><div style="font-size:0.85rem;color:rgba(61,26,14,0.7);line-height:1.65;">${c.adminNote}</div></div>`:''}
    <div style="text-align:center;margin-top:20px;">
      <a href="${STORE_URL}/#custom" style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;text-decoration:none;padding:13px 32px;border-radius:999px;font-weight:800;font-size:0.8rem;letter-spacing:2px;text-transform:uppercase;">Track Commission →</a>
    </div>`)
}

// Coupon validate (public)
app.post('/api/coupons/validate', async (req,res) => {
    try {
        const { code, cartTotal } = req.body;
        if (!code) return res.status(400).json({ valid:false, message:'Coupon code required' });
        const c = await Coupon.findOne({ code:code.toUpperCase().trim(), status:'Active' });
        if (!c) return res.status(400).json({ valid:false, message:'Invalid coupon code' });
        if (c.maxUses && c.usedCount >= c.maxUses) return res.status(400).json({ valid:false, message:'Coupon usage limit reached' });
        if (c.expires && new Date() > new Date(c.expires)) return res.status(400).json({ valid:false, message:'Coupon has expired' });
        if (c.min && cartTotal < c.min) return res.status(400).json({ valid:false, message:`Minimum order ₹${c.min} required` });
        const discount = c.type === 'pct' ? Math.round(cartTotal * c.val / 100) : c.val;
        res.json({ valid:true, discount, label:c.desc, code:c.code, type:c.type, val:c.val });
    } catch { res.status(500).json({ valid:false, message:'Server error' }); }
});

// Public settings

app.get('/api/settings/public', async (_,res) => {
    try {
        const keys = ['store.name','store.tagline','store.whatsapp','store.instagram','shipping.freeAbove','shipping.fee','shipping.days','shipping.cod','marquee.items'];
        const settings = await Settings.find({ key:{ $in:keys } });
        res.json({ settings: Object.fromEntries(settings.map(s=>[s.key,s.value])) });
    } catch { res.status(500).json({ message:'Server error' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTH
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/auth/register', authLimiter, async (req,res) => {
    try {
        const { name, email, phone, password } = req.body;
        const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
        const phoneRx = /^[6-9]\d{9}$/;
        const cleanPhone = (v='') => v.replace(/\D/g,'').replace(/^0+/,'').replace(/^91/,'');
        if (!name || name.trim().length < 2)           return res.status(400).json({ message:'Name must be at least 2 characters' });
        if (!email || !emailRx.test(email.trim().toLowerCase())) return res.status(400).json({ message:'Enter a valid email address' });
        if (phone && !phoneRx.test(cleanPhone(phone)))  return res.status(400).json({ message:'Phone must be a valid 10-digit Indian mobile number' });
        if (!password || password.length < 6)           return res.status(400).json({ message:'Password must be at least 6 characters' });
        if (await User.findOne({ email:email.toLowerCase().trim() })) return res.status(409).json({ message:'An account with this email already exists' });
        const hash = await bcrypt.hash(password, 12);
        const cleanedPhone = phone ? cleanPhone(phone) : '';
        const user = await User.create({ name:name.trim(), email:email.toLowerCase().trim(), phone:cleanedPhone, password:hash });
        const token = jwt.sign({ id:user._id }, process.env.JWT_SECRET, { expiresIn:process.env.JWT_EXPIRES_IN||'7d' });
        sendMail(user.email, `Welcome to Design Den, ${user.name}! 🌸`, welcomeEmail(user.name));
        res.status(201).json({ token, user:{ id:user._id, name:user.name, email:user.email, phone:user.phone } });
    } catch(err) { console.error('[register]',err); res.status(500).json({ message:'Registration failed' }); }
});
app.post('/api/auth/login', authLimiter, async (req,res) => {
    try {
        const { email, password } = req.body;
        const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
        if (!email || !emailRx.test(email.trim().toLowerCase())) return res.status(400).json({ message:'Enter a valid email address' });
        if (!password) return res.status(400).json({ message:'Please enter your password' });
        const user = await User.findOne({ email:email.toLowerCase().trim() });
        if (!user) return res.status(401).json({ message:'No account found with this email' });
        if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ message:'Incorrect password. Please try again.' });
        const token = jwt.sign({ id:user._id }, process.env.JWT_SECRET, { expiresIn:'7d' });
        res.json({ token, user:{ id:user._id, name:user.name, email:user.email, phone:user.phone } });
    } catch { res.status(500).json({ message:'Login failed' }); }
});
app.post('/api/auth/admin-login', adminLoginLimiter, async (req,res) => {
    try {
        const { key } = req.body;
        if (!key || key !== process.env.ADMIN_KEY) return res.status(401).json({ message:'Invalid admin key' });
        const token = jwt.sign({ isAdmin:true }, process.env.JWT_SECRET, { expiresIn:'12h' });
        res.json({ token });
    } catch { res.status(500).json({ message:'Server error' }); }
});
app.get('/api/auth/me', auth, async (req,res) => {
    try {
        const user = await User.findById(req.user.id).select('-password -__v');
        if (!user) return res.status(404).json({ message:'User not found' });
        res.json({ user });
    } catch { res.status(500).json({ message:'Server error' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  CART & WISHLIST
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/cart',     auth, async (req,res) => { try{const c=await Cart.findOne({userId:req.user.id});res.json({items:c?c.items:[]});}catch{res.status(500).json({message:'Server error'});} });
app.put('/api/cart',     auth, async (req,res) => { try{await Cart.findOneAndUpdate({userId:req.user.id},{items:req.body.items||[],updatedAt:new Date()},{upsert:true,new:true});res.json({success:true});}catch{res.status(500).json({message:'Server error'});} });
app.get('/api/wishlist', auth, async (req,res) => { try{const w=await Wishlist.findOne({userId:req.user.id});res.json({items:w?w.items:[]});}catch{res.status(500).json({message:'Server error'});} });
app.put('/api/wishlist', auth, async (req,res) => { try{await Wishlist.findOneAndUpdate({userId:req.user.id},{items:req.body.items||[],updatedAt:new Date()},{upsert:true,new:true});res.json({success:true});}catch{res.status(500).json({message:'Server error'});} });

// ═══════════════════════════════════════════════════════════════════════════════
//  PRICING — server is the source of truth
// ═══════════════════════════════════════════════════════════════════════════════
async function computeTrustedOrderTotals(items, couponCode) {
    if (!Array.isArray(items) || !items.length) throw new Error('Cart is empty');

    const ids = items.map(i => i._id || i.productId).filter(Boolean);
    const dbProducts = await Product.find({ _id: { $in: ids } });
    const productMap = new Map(dbProducts.map(p => [String(p._id), p]));

    // NEW: resolves the correct trusted price for a cart item, accounting for
    // variants. If the item specifies a variantId, the price comes from that
    // SPECIFIC variant in the DB (never trusting any price the client sent) —
    // same trust model as before, just variant-aware. Falls back to the
    // product's own price when there's no variantId (non-variant product).
    function resolveTrustedPrice(product, item) {
        if (item.variantId && product.variants && product.variants.length) {
            const v = product.variants.find(v => v.variantId === item.variantId);
            if (!v) throw new Error(`Variant not found: ${item.variantId} on ${product.name}`);
            if (!v.active) throw new Error(`"${product.name} — ${v.label}" is no longer available`);
            return v.price;
        }
        return product.price;
    }

    let subtotal = 0;
    for (const item of items) {
        const pid = String(item._id || item.productId || '');
        const qty = Math.max(1, parseInt(item.qty, 10) || 1);
        const product = productMap.get(pid);
        if (!product) throw new Error(`Product not found: ${pid}`);
        subtotal += resolveTrustedPrice(product, item) * qty;
    }

    let discount = 0, appliedCoupon = null;
    if (couponCode) {
        const c = await Coupon.findOne({ code: String(couponCode).toUpperCase() });
        if (c && c.status === 'Active'
            && !(c.maxUses && c.usedCount >= c.maxUses)
            && !(c.expires && new Date() > new Date(c.expires))
            && !(c.min && subtotal < c.min)) {
            discount = c.type === 'pct' ? Math.round(subtotal * c.val / 100) : c.val;
            appliedCoupon = c.code;
        }
    }

    const shipSettings = await Settings.find({ key: { $in: ['shipping.fee','shipping.freeAbove'] } });
    const sMap   = Object.fromEntries(shipSettings.map(s => [s.key, s.value]));
    const fee       = parseFloat(sMap['shipping.fee']);
    const freeAbove = parseFloat(sMap['shipping.freeAbove']);
    const shippingFee       = isNaN(fee) ? 99 : fee;
    const shippingFreeAbove = isNaN(freeAbove) ? 999 : freeAbove;
    const netSubtotal = subtotal - discount;
    const shipping = netSubtotal >= shippingFreeAbove ? 0 : shippingFee;

    const total = subtotal - discount + shipping;
    return { subtotal, discount, coupon: appliedCoupon, shipping, total };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ORDERS (User-facing)
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/orders', auth, async (req,res) => {
    try { res.json({ orders: await Order.find({ userId:req.user.id }).sort({ createdAt:-1 }).select('-__v -userId') }); }
    catch { res.status(500).json({ message:'Server error' }); }
});
app.get('/api/orders/:orderId', auth, async (req,res) => {
    try {
        const o = await Order.findOne({ id:req.params.orderId, userId:req.user.id });
        if (!o) return res.status(404).json({ message:'Order not found' });
        res.json({ order:o });
    } catch { res.status(500).json({ message:'Server error' }); }
});
// NEW: guest order tracking — no account, no login, so lookup is by order ID +
// the email used at checkout (same pattern as the existing commission tracker).
// Scoped to guest orders only (isGuestOrder:true) — a guest providing someone's
// order ID can't use this to peek at a logged-in customer's order, since those
// don't have guestEmail set and this query filters strictly on it.
app.post('/api/orders/track', async (req,res) => {
    try {
        const { orderId, email } = req.body;
        const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
        if (!orderId) return res.status(400).json({ message:'Order ID is required' });
        if (!email || !emailRx.test(String(email).trim().toLowerCase())) return res.status(400).json({ message:'Enter a valid email address' });
        const o = await Order.findOne({
            id: String(orderId).trim().toUpperCase(),
            isGuestOrder: true,
            guestEmail: String(email).trim().toLowerCase()
        }).select('-__v');
        if (!o) return res.status(404).json({ message:'Order not found. Check your Order ID and email.' });
        res.json({ order:o });
    } catch { res.status(500).json({ message:'Server error' }); }
});
app.post('/api/orders', optionalAuth, async (req,res) => {
    // ── Stock handling rewritten: previously stock was decremented AFTER order
    // creation, in a loop, with no atomicity — two simultaneous orders for the
    // last unit of a product could both succeed (overselling), and a failed
    // decrement was only console.warn'd, silently leaving stock wrong forever.
    // Fix: reserve stock atomically per item BEFORE creating the order, using a
    // conditional update (stock >= qty) so concurrent requests can't both win.
    // If any item can't be reserved, roll back everything already reserved and
    // fail the whole order — no partial/oversold orders.
    //
    // NEW (variants): when an item carries a variantId, the reservation targets
    // that specific variant's stock field inside the variants array, using
    // Mongo's arrayFilters to update only the matching array element atomically.
    // Items without a variantId behave exactly as before (product-level stock).
    const reserved = []; // tracks {productId, variantId|null, qty} successfully decremented, for rollback
    try {
        const { items, status, date, address, payment, coupon, guestEmail, guestPhone } = req.body; // Removed client-sent `id`
        if (!items || !items.length) return res.status(400).json({ message:'Missing required fields' });

        // NEW: guest checkout. If there's no logged-in user (req.user is null from
        // optionalAuth), this order has no account behind it — we still need a way
        // to reach the customer and let them look up their order later, so email
        // is required for guests (phone strongly recommended, used for delivery).
        const isGuest = !req.user;
        if (isGuest) {
            const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
            if (!guestEmail || !emailRx.test(String(guestEmail).trim().toLowerCase())) {
                return res.status(400).json({ message:'A valid email is required to place an order as a guest.' });
            }
        }

        const { subtotal, discount, coupon:appliedCoupon, shipping, total } = await computeTrustedOrderTotals(items, coupon);

        // ── Atomically reserve stock for every item, one at a time ──
        for (const item of items) {
            const pid = item._id || item.productId;
            const variantId = item.variantId || null;
            const qty = Math.max(1, parseInt(item.qty, 10) || 1);
            if (!pid) continue;

            let updated;
            if (variantId) {
                updated = await Product.findOneAndUpdate(
                    { _id: pid, variants: { $elemMatch: { variantId, stock: { $gte: qty } } } },
                    { $inc: { 'variants.$[v].stock': -qty }, updatedAt: new Date() },
                    { new: true, arrayFilters: [{ 'v.variantId': variantId }] }
                );
                if (updated) await updated.save(); // re-run pre-save hook to refresh derived top-level stock/price
            } else {
                updated = await Product.findOneAndUpdate(
                    { _id: pid, stock: { $gte: qty } },        // only matches if enough stock remains
                    { $inc: { stock: -qty }, updatedAt: new Date() },
                    { new: true }
                );
            }

            if (!updated) {
                // Not enough stock (or product/variant missing) — roll back everything reserved so far
                for (const r of reserved) {
                    if (r.variantId) {
                        await Product.findOneAndUpdate(
                            { _id: r.productId },
                            { $inc: { 'variants.$[v].stock': r.qty } },
                            { arrayFilters: [{ 'v.variantId': r.variantId }] }
                        ).catch(()=>{});
                    } else {
                        await Product.findByIdAndUpdate(r.productId, { $inc: { stock: r.qty } }).catch(()=>{});
                    }
                }
                const p = await Product.findById(pid).select('name stock variants');
                const variantLabel = variantId && p ? p.variants.find(v=>v.variantId===variantId)?.label : null;
                const availableStock = variantId && p ? (p.variants.find(v=>v.variantId===variantId)?.stock ?? 0) : p?.stock;
                return res.status(409).json({
                    message: p
                        ? `Sorry, "${p.name}${variantLabel ? ' — '+variantLabel : ''}" only has ${availableStock} left in stock. Please update your cart.`
                        : 'One of the items in your cart is no longer available.'
                });
            }
            reserved.push({ productId: pid, variantId, qty });
        }

        // Fetch default delivery days from Settings
        const shipDaysSetting = await Settings.findOne({ key: 'shipping.days' });
        const defaultDeliveryDays = shipDaysSetting ? parseInt(shipDaysSetting.value, 10) || 2 : 2;

        // Generate Server-side DD prefix order ID
        const orderId = `DD-${Date.now().toString(36).toUpperCase()}${Math.random().toString(36).substring(2, 5).toUpperCase()}`;

        let order;
        try {
            order = await Order.create({
                userId: req.user ? req.user.id : null,
                guestEmail: isGuest ? String(guestEmail).trim().toLowerCase() : '',
                guestPhone: isGuest ? String(guestPhone || '').trim() : '',
                isGuestOrder: isGuest,
                id: orderId,
                items,
                total,
                shipping,
                discount,
                coupon:appliedCoupon,
                status:status||'Placed',
                date,
                address,
                payment,
                deliveryDays: defaultDeliveryDays
            });
        } catch (createErr) {
            // Order creation failed AFTER stock was reserved — roll back stock before re-throwing.
            // NEW: variant-aware rollback (previously this only handled product-level stock).
            for (const r of reserved) {
                if (r.variantId) {
                    await Product.findOneAndUpdate(
                        { _id: r.productId },
                        { $inc: { 'variants.$[v].stock': r.qty } },
                        { arrayFilters: [{ 'v.variantId': r.variantId }] }
                    ).catch(()=>{});
                } else {
                    await Product.findByIdAndUpdate(r.productId, { $inc: { stock: r.qty } }).catch(()=>{});
                }
            }
            throw createErr;
        }

        if (appliedCoupon) await Coupon.findOneAndUpdate({ code:appliedCoupon },{ $inc:{ usedCount:1 } });
        // NEW: only registered accounts accumulate totalSpent/orderCount — guests have no User document
        if (req.user) await User.findByIdAndUpdate(req.user.id, { $inc:{ totalSpent:total, orderCount:1 } });

        res.status(201).json({ order });
    } catch(err) {
        if (err.code === 11000) return res.status(409).json({ message:'Duplicate order ID – try again' });
        console.error('[POST /orders]',err); res.status(400).json({ message: err.message || 'Server error' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  PAYMENT — Razorpay
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/payment/create-order', optionalAuth, async (req,res) => {
    try {
        const { items, coupon } = req.body;
        const { total } = await computeTrustedOrderTotals(items, coupon);
        if (!total || total <= 0) return res.status(400).json({ message:'Invalid amount' });
        const rzpOrder = await razorpay.orders.create({ amount:Math.round(total*100), currency:'INR', receipt:`DD_${Date.now().toString(36)}` });
        res.json({ orderId:rzpOrder.id, amount:rzpOrder.amount, key:process.env.RAZORPAY_KEY_ID, total });
    } catch(err) { res.status(500).json({ message:'Payment order creation failed: '+err.message }); }
});
app.post('/api/payment/verify', optionalAuth, (req,res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
        const expected = crypto.createHmac('sha256',process.env.RAZORPAY_KEY_SECRET).update(razorpay_order_id+'|'+razorpay_payment_id).digest('hex');
        if (expected === razorpay_signature) res.json({ success:true });
        else res.status(400).json({ success:false, message:'Signature mismatch' });
    } catch { res.status(500).json({ success:false, message:'Verification error' }); }
});

// ── Razorpay webhook — source of truth for payment confirmation ──────────────
// NEW: previously, order/payment confirmation depended entirely on the browser
// calling /api/payment/verify after checkout. If the customer closed the tab
// right after paying (slow network, accidental close, app backgrounded on
// mobile) but before that call fired, Razorpay would have the money and your
// DB would never know — order stuck at "Placed" with no payment record.
//
// This webhook is called directly by Razorpay's servers (not the browser), so
// it fires independently of what the customer's device does. Configure the
// webhook URL in your Razorpay Dashboard → Settings → Webhooks as:
//   https://yourdomain.com/api/payment/webhook
// and set RAZORPAY_WEBHOOK_SECRET in your .env to the secret shown there
// (this is a DIFFERENT secret from RAZORPAY_KEY_SECRET).
//
// Uses express.raw() instead of express.json() because Razorpay signs the
// exact raw request body — re-serializing parsed JSON can produce a different
// byte string and break signature verification.
app.post('/api/payment/webhook', express.raw({ type:'application/json' }), async (req,res) => {
    try {
        const signature = req.headers['x-razorpay-signature'];
        const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
        if (!secret) { console.warn('⚠️  RAZORPAY_WEBHOOK_SECRET not set — webhook disabled'); return res.status(200).send('ok'); }
        if (!signature) return res.status(400).send('Missing signature');

        const expected = crypto.createHmac('sha256', secret).update(req.body).digest('hex');
        if (expected !== signature) { console.warn('⚠️  Webhook signature mismatch'); return res.status(400).send('Invalid signature'); }

        const event = JSON.parse(req.body.toString('utf8'));
        // Respond fast — Razorpay retries on timeout/non-2xx, so ack immediately,
        // then process. (Kept synchronous here for simplicity; fine at this scale.)
        if (event.event === 'payment.captured' || event.event === 'order.paid') {
            const rzpOrderId = event.payload?.payment?.entity?.order_id || event.payload?.order?.entity?.id;
            const paymentId  = event.payload?.payment?.entity?.id;
            if (rzpOrderId) {
                const updated = await Order.findOneAndUpdate(
                    { 'payment.razorpayOrderId': rzpOrderId, status:'Placed' },
                    { $set: { 'payment.txnId': paymentId, status:'Confirmed' } },
                    { new:true }
                );
                if (updated) console.log(`✅ Webhook confirmed payment for order ${updated.id}`);
            }
        }
        res.status(200).send('ok');
    } catch(err) {
        console.error('[payment/webhook]', err);
        res.status(200).send('ok'); // ack anyway — don't let Razorpay retry-storm on our bugs
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  ADMIN — Products
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/products', adminAuth, async (req,res) => {
    try {
        const { search, category, badge, sort } = req.query;
        const q = {};
        if (category && category !== 'all') q.category = category;
        if (badge) q.badge = badge;
        if (search) { const re = new RegExp(search.trim(),'i'); q.$or = [{ name:re },{ desc:re },{ sku:re }]; }
        let query = Product.find(q);
        if (sort === 'price_asc')       query = query.sort({ price:1 });
        else if (sort === 'price_desc') query = query.sort({ price:-1 });
        else if (sort === 'stock')      query = query.sort({ stock:1 });
        else query = query.sort({ createdAt:-1 });
        res.json({ products: await query });
    } catch { res.status(500).json({ message:'Failed to fetch products' }); }
});
app.post('/api/admin/products',              adminAuth, async (req,res) => { try{res.status(201).json({product:await Product.create({...req.body,updatedAt:new Date()})});}catch(e){res.status(400).json({message:e.message});} });
// NEW: switched from findByIdAndUpdate to find+save. findByIdAndUpdate does NOT
// run Mongoose pre('save') hooks by default — that would silently skip the
// variant price/stock sync hook above whenever a product was edited via this
// route, leaving the top-level price/stock stale and out of sync with variants.
app.put('/api/admin/products/:id', adminAuth, async (req,res) => {
    try {
        const p = await Product.findById(req.params.id);
        if (!p) return res.status(404).json({ message:'Not found' });
        Object.assign(p, req.body, { updatedAt:new Date() });
        await p.save(); // runs validators + the pre-save variant sync hook
        res.json({ product:p });
    } catch(e) { res.status(400).json({ message:e.message }); }
});
app.patch('/api/admin/products/:id/stock',   adminAuth, async (req,res) => {
    try {
        const { stock, delta } = req.body;
        const p = await Product.findById(req.params.id);
        if (!p) return res.status(404).json({ message:'Not found' });
        if (p.variants && p.variants.length) {
            // NEW: with variants present, top-level stock is a derived sum — editing
            // it directly here would be silently overwritten by the next save's sync
            // hook anyway. Point the admin at the correct endpoint instead of letting
            // them think the edit took effect.
            return res.status(400).json({ message:'This product has variants — update stock per-variant via PATCH /api/admin/products/:id/variants/:variantId/stock' });
        }
        if (delta!==undefined) p.stock=Math.max(0,p.stock+delta);
        else if (stock!==undefined) p.stock=Math.max(0,stock);
        p.updatedAt=new Date();
        await p.save();
        res.json({ product:p });
    } catch(e) { res.status(400).json({ message:e.message }); }
});
// NEW: dedicated route for adjusting a single variant's stock without touching
// the others. Used by the admin "quick stock update" UI when a product has
// variants (color/weight options), each tracked independently.
app.patch('/api/admin/products/:id/variants/:variantId/stock', adminAuth, async (req,res) => {
    try {
        const { stock, delta } = req.body;
        const p = await Product.findById(req.params.id);
        if (!p) return res.status(404).json({ message:'Product not found' });
        const v = p.variants.find(v => v.variantId === req.params.variantId);
        if (!v) return res.status(404).json({ message:'Variant not found' });
        if (delta!==undefined) v.stock = Math.max(0, v.stock + delta);
        else if (stock!==undefined) v.stock = Math.max(0, stock);
        p.updatedAt = new Date();
        await p.save(); // re-syncs top-level stock total via the pre-save hook
        res.json({ product:p });
    } catch(e) { res.status(400).json({ message:e.message }); }
});
app.patch('/api/admin/products/:id/toggle',  adminAuth, async (req,res) => { try{const{field}=req.body;if(!['featured','active'].includes(field))return res.status(400).json({message:'Invalid field'});const p=await Product.findById(req.params.id);if(!p)return res.status(404).json({message:'Not found'});p[field]=!p[field];p.updatedAt=new Date();await p.save();res.json({product:p});}catch{res.status(500).json({message:'Server error'});} });
app.delete('/api/admin/products/:id',        adminAuth, async (req,res) => { try{const p=await Product.findByIdAndUpdate(req.params.id,{active:false,updatedAt:new Date()},{new:true});if(!p)return res.status(404).json({message:'Not found'});res.json({success:true});}catch{res.status(500).json({message:'Failed to delete'});} });

// ═══════════════════════════════════════════════════════════════════════════════
//  ADMIN — Orders
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/orders', adminAuth, async (req,res) => {
    try {
        const { status, page=1, limit=200 } = req.query;
        const q = status ? { status } : {};
        const [orders, total] = await Promise.all([
            Order.find(q).sort({ createdAt:-1 }).skip((page-1)*parseInt(limit)).limit(parseInt(limit)).populate('userId','name email phone'),
            Order.countDocuments(q)
        ]);
        res.json({ orders, total });
    } catch { res.status(500).json({ message:'Failed to fetch orders' }); }
});
app.put('/api/admin/orders/:id/status', adminAuth, async (req,res) => {
    try {
        const { status, adminNote, deliveryDays } = req.body; // Added deliveryDays override
        const update = { status };
        if (adminNote !== undefined) update.adminNote = adminNote;
        if (deliveryDays !== undefined) update.deliveryDays = deliveryDays; 
        
        const order = await Order.findOneAndUpdate({ id:req.params.id }, update, { new:true });
        if (!order) return res.status(404).json({ message:'Order not found' });
        res.json({ order });
    } catch { res.status(500).json({ message:'Failed to update order' }); }
});

// ── Admin stats ───────────────────────────────────────────────────────────────
app.get('/api/admin/stats', adminAuth, async (_,res) => {
    try {
        const [products, orders, users, revenueAgg] = await Promise.all([
            Product.countDocuments({ active:true }),
            Order.countDocuments(),
            User.countDocuments(),
            Order.aggregate([{ $match:{ status:{ $ne:'Cancelled' } } },{ $group:{ _id:null, total:{ $sum:'$total' } } }])
        ]);
        const statusCounts   = await Order.aggregate([{ $group:{ _id:'$status', count:{ $sum:1 } } }]);
        const lowStock       = await Product.countDocuments({ active:true, stock:{ $gt:0, $lt:10 } });
        const outStock       = await Product.countDocuments({ active:true, stock:0 });
        const pendingTestis  = await Testimonial.countDocuments({ status:'Pending' });
        const newCommissions = await Commission.countDocuments({ status:'New' });
        const failedEmails   = await EmailLog.countDocuments({ status:'failed' }); // NEW
        res.json({ products, orders, users, lowStock, outStock, revenue:revenueAgg[0]?.total||0, statusCounts:Object.fromEntries(statusCounts.map(s=>[s._id,s.count])), pendingTestis, newCommissions, failedEmails });
    } catch(err) { console.error('[stats]',err); res.status(500).json({ message:'Failed to fetch stats' }); }
});

// ── Admin coupons ─────────────────────────────────────────────────────────────
app.get('/api/admin/coupons',        adminAuth, async (_,res)   => { try{res.json({coupons:await Coupon.find().sort({createdAt:-1})});}catch{res.status(500).json({message:'Error'});} });
app.post('/api/admin/coupons',       adminAuth, async (req,res) => { try{res.status(201).json({coupon:await Coupon.create(req.body)});}catch(e){res.status(400).json({message:e.message});} });
app.put('/api/admin/coupons/:id',    adminAuth, async (req,res) => { try{const c=await Coupon.findByIdAndUpdate(req.params.id,req.body,{new:true,runValidators:true});if(!c)return res.status(404).json({message:'Not found'});res.json({coupon:c});}catch(e){res.status(400).json({message:e.message});} });
app.delete('/api/admin/coupons/:id', adminAuth, async (req,res) => { try{await Coupon.findByIdAndDelete(req.params.id);res.json({success:true});}catch{res.status(500).json({message:'Error'});} });

// ── Admin patterns ────────────────────────────────────────────────────────────
app.get('/api/admin/patterns',        adminAuth, async (_,res)   => { try{res.json({patterns:await Pattern.find().sort({createdAt:-1})});}catch{res.status(500).json({message:'Error'});} });
app.post('/api/admin/patterns',       adminAuth, async (req,res) => { try{res.status(201).json({pattern:await Pattern.create(req.body)});}catch(e){res.status(400).json({message:e.message});} });
app.put('/api/admin/patterns/:id',    adminAuth, async (req,res) => { try{const p=await Pattern.findByIdAndUpdate(req.params.id,req.body,{new:true});if(!p)return res.status(404).json({message:'Not found'});res.json({pattern:p});}catch(e){res.status(400).json({message:e.message});} });
app.delete('/api/admin/patterns/:id', adminAuth, async (req,res) => { try{await Pattern.findByIdAndDelete(req.params.id);res.json({success:true});}catch{res.status(500).json({message:'Error'});} });

// ── Admin testimonials ────────────────────────────────────────────────────────
app.get('/api/admin/testimonials',        adminAuth, async (_,res)   => { try{res.json({testimonials:await Testimonial.find().sort({createdAt:-1})});}catch{res.status(500).json({message:'Error'});} });
app.post('/api/admin/testimonials',       adminAuth, async (req,res) => { try{res.status(201).json({testimonial:await Testimonial.create(req.body)});}catch(e){res.status(400).json({message:e.message});} });
app.put('/api/admin/testimonials/:id',    adminAuth, async (req,res) => { try{const t=await Testimonial.findByIdAndUpdate(req.params.id,req.body,{new:true});if(!t)return res.status(404).json({message:'Not found'});res.json({testimonial:t});}catch(e){res.status(400).json({message:e.message});} });
app.delete('/api/admin/testimonials/:id', adminAuth, async (req,res) => { try{await Testimonial.findByIdAndDelete(req.params.id);res.json({success:true});}catch{res.status(500).json({message:'Error'});} });

// ── Admin gallery ─────────────────────────────────────────────────────────────
app.get('/api/admin/gallery',        adminAuth, async (_,res)   => { try{res.json({images:await Gallery.find().sort({sortOrder:1,createdAt:1})});}catch{res.status(500).json({message:'Error'});} });
app.post('/api/admin/gallery',       adminAuth, async (req,res) => { try{res.status(201).json({image:await Gallery.create(req.body)});}catch(e){res.status(400).json({message:e.message});} });
app.put('/api/admin/gallery/:id',    adminAuth, async (req,res) => { try{const g=await Gallery.findByIdAndUpdate(req.params.id,req.body,{new:true});if(!g)return res.status(404).json({message:'Not found'});res.json({image:g});}catch(e){res.status(400).json({message:e.message});} });
app.delete('/api/admin/gallery/:id', adminAuth, async (req,res) => { try{await Gallery.findByIdAndDelete(req.params.id);res.json({success:true});}catch{res.status(500).json({message:'Error'});} });

// ── Admin commissions ─────────────────────────────────────────────────────────
app.get('/api/admin/commissions', adminAuth, async (req,res) => {
    try {
        const { status } = req.query;
        const q = status ? { status } : {};
        const commissions = await Commission.find(q).sort({ createdAt:-1 });
        const newCount = await Commission.countDocuments({ status:'New' });
        res.json({ commissions, total:commissions.length, newCount });
    } catch { res.status(500).json({ message:'Error' }); }
});
app.put('/api/admin/commissions/:id', adminAuth, async (req,res) => {
    try {
        const prev = await Commission.findById(req.params.id);
        if (!prev) return res.status(404).json({ message:'Not found' });
        const update = { ...req.body };
        if (update.status === 'Completed' && !prev.completedAt) update.completedAt = new Date();
        const c = await Commission.findByIdAndUpdate(req.params.id, update, { new:true, runValidators:true });
        const statusChanged = prev.status !== c.status;
        const noteChanged   = req.body.adminNote !== undefined && prev.adminNote !== c.adminNote;
        if ((statusChanged || noteChanged) && c.email) {
            sendMail(c.email, `Commission Update — ${c.commissionId} (${c.status}) 🎨`, commissionStatusEmail(c));
        }
        res.json({ commission:c });
    } catch(e) { res.status(400).json({ message:e.message }); }
});
app.delete('/api/admin/commissions/:id', adminAuth, async (req,res) => { try{await Commission.findByIdAndDelete(req.params.id);res.json({success:true});}catch{res.status(500).json({message:'Error'});} });

// ── Admin customers ───────────────────────────────────────────────────────────
app.get('/api/admin/customers', adminAuth, async (req,res) => {
    try {
        const { search } = req.query;
        const q = search ? { $or:[{ name:new RegExp(search,'i') },{ email:new RegExp(search,'i') }] } : {};
        const users = await User.find(q).select('-password -__v').sort({ createdAt:-1 });
        const counts = await Order.aggregate([{ $group:{ _id:'$userId', count:{ $sum:1 }, total:{ $sum:'$total' } } }]);
        // NEW: guest orders have userId:null, which now shows up as a `_id: null`
        // group here. Filter it out before building the lookup map — calling
        // .toString() on a null _id would otherwise throw and crash this whole
        // endpoint. Guest orders correctly have no per-user stats to attach to.
        const map = Object.fromEntries(counts.filter(c => c._id).map(c=>[c._id.toString(),c]));
        res.json({ customers: users.map(u => ({ ...u.toObject(), orderCount:map[u._id.toString()]?.count||0, totalSpent:map[u._id.toString()]?.total||0 })) });
    } catch { res.status(500).json({ message:'Failed to fetch customers' }); }
});

// ── Admin email log ───────────────────────────────────────────────────────────
// NEW: surfaces failed sends (order confirmations, pattern deliveries, welcome
// emails, commission updates) so they don't go unnoticed. Most recent first;
// failures bubbled to the top via sort. Add a UI tab for this in admin.html
// whenever convenient — for now it's reachable via GET request or curl.
app.get('/api/admin/email-log', adminAuth, async (req,res) => {
    try {
        const { status } = req.query; // optional: 'failed' or 'sent'
        const q = status ? { status } : {};
        const logs = await EmailLog.find(q).sort({ createdAt:-1 }).limit(200);
        const failedCount = await EmailLog.countDocuments({ status:'failed' });
        res.json({ logs, failedCount });
    } catch { res.status(500).json({ message:'Failed to fetch email log' }); }
});

// ── Admin settings ────────────────────────────────────────────────────────────
app.get('/api/admin/settings', adminAuth, async (_,res) => {
    try { const s = await Settings.find(); res.json({ settings:Object.fromEntries(s.map(x=>[x.key,x.value])) }); }
    catch { res.status(500).json({ message:'Server error' }); }
});
app.put('/api/admin/settings', adminAuth, async (req,res) => {
    try {
        await Promise.all(Object.entries(req.body).map(([key,value]) => Settings.findOneAndUpdate({ key },{ value },{ upsert:true, new:true })));
        res.json({ success:true });
    } catch { res.status(500).json({ message:'Server error' }); }
});

// ─── 404 / Error ──────────────────────────────────────────────────────────────
// NOTE: no path argument here (not '*') — Express 5's router (path-to-regexp v8)
// rejects the bare '*' wildcard and throws PathError at startup. Express 4 accepts
// either form, so omitting the path keeps this working regardless of which major
// version actually gets installed.
app.use((req,res) => res.status(404).json({ message:`${req.method} ${req.originalUrl} not found` }));
app.use((err,req,res,_next) => {
    // NEW: CORS rejections get their own clear response instead of falling
    // through to the generic 500 below — makes a future origin mismatch
    // immediately diagnosable from the response itself (and from the
    // "CORS rejected request from origin" warning already logged above),
    // rather than looking like an unrelated server crash.
    if (err.message === 'Not allowed by CORS') {
        return res.status(403).json({ message:'This origin is not permitted to access the API.' });
    }
    console.error('[Unhandled]',err); res.status(500).json({ message:'Internal server error' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
    console.log('\n🧶 ══════════════════════════════════════════════');
    console.log(`   Design Den API  →  http://localhost:${PORT}`);
    console.log('══════════════════════════════════════════════════\n');
    try { await seedDB(); } catch(e) { console.error('Seed error:', e.message); }
});