// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  DESIGN DEN — Backend API Server                                         ║
// ║  Node.js + Express + MongoDB + Razorpay + Nodemailer                     ║
// ╚══════════════════════════════════════════════════════════════════════════╝
require('dotenv').config();
const dns = require('dns');
const { promisify } = require('util');
const resolve4 = promisify(dns.resolve4);

// ─── FORCE IPv4 GLOBALLY ────────────────────────────────────────────────────
// Render, Railway, and similar platforms lack outbound IPv6. If Node ever
// resolves an IPv6 address, the connection will fail with ENETUNREACH.
// This monkey‑patch makes every dns.lookup() call request only A (IPv4)
// records, preventing IPv6 connections entirely.
dns.setDefaultResultOrder('ipv4first');            // prefer A over AAAA
const _nativeLookup = dns.lookup;
dns.lookup = (hostname, options, callback) => {
    if (typeof options === 'function') {
        callback = options;
        options = {};
    }
    options = options || {};
    options.family = 4;                             // force IPv4
    return _nativeLookup(hostname, options, callback);
};
// ────────────────────────────────────────────────────────────────────────────

const express     = require('express');
const mongoose    = require('mongoose');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const cors        = require('cors');
const Razorpay    = require('razorpay');
const crypto      = require('crypto');
const nodemailer  = require('nodemailer');
const helmet      = require('helmet');
const rateLimit   = require('express-rate-limit');

const app = express();

// ─── Trust proxy ──────────────────────────────────────────────────────────────
app.set('trust proxy', 1);

// ─── Security headers ─────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy:false, crossOriginEmbedderPolicy:false }));

// ─── Middleware ───────────────────────────────────────────────────────────────
const DEFAULT_ALLOWED_ORIGINS = [
    'https://design-den-studio.vercel.app',
];
const EXTRA_ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
const STORE_URL = (process.env.STORE_URL || 'https://design-den-studio.vercel.app').replace(/\/+$/, '');
const ADMIN_NOTIFY_EMAIL = process.env.ADMIN_NOTIFY_EMAIL || '';

const stripTrailingSlash = (s) => s.replace(/\/+$/, '');
const ALLOWED_ORIGINS = [...new Set([...DEFAULT_ALLOWED_ORIGINS, ...EXTRA_ALLOWED_ORIGINS].map(stripTrailingSlash))];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (origin === 'null') return callback(null, true);
        if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return callback(null, true);
        if (ALLOWED_ORIGINS.includes(stripTrailingSlash(origin))) return callback(null, true);
        console.warn(`⚠️  CORS rejected request from origin: ${origin}`);
        callback(new Error('Not allowed by CORS'));
    },
    methods:['GET','POST','PUT','DELETE','PATCH','OPTIONS'],
    allowedHeaders:['Content-Type','Authorization','X-Admin-Key'],
    credentials:false,
    optionsSuccessStatus:200
}));
app.use(express.json({ limit:'30mb' }));
app.use((req,_,next)=>{ console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.path}`); next(); });

// ─── Rate limiters ────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message:'Too many attempts. Please try again in a few minutes.' }
});
const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message:'Too many attempts. Please try again in a few minutes.' }
});
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message:'Too many requests. Please slow down.' }
});
app.use('/api/', apiLimiter);

app.get('/', (_,res) => res.json({ status: 'ok', message: 'Design Den API Server', frontend: STORE_URL }));

// ─── MongoDB ──────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI, { dbName:'design_den' })
    .then(()=> console.log('✅ MongoDB connected'))
    .catch(err=>{ console.error('❌ MongoDB:', err.message); process.exit(1); });

// ═══════════════════════════════════════════════════════════════════════════════
//  SCHEMAS & MODELS
// ═══════════════════════════════════════════════════════════════════════════════

const variantSchema = new mongoose.Schema({
    variantId: { type:String, required:true },
    label:     { type:String, required:true, trim:true },
    type:      { type:String, default:'option', enum:['color','Types','option'] },
    swatch:    { type:String, default:'' },
    img:       { type:String, default:'' },
    price:     { type:Number, required:true, min:0 },
    stock:     { type:Number, required:true, default:0, min:0 },
    sku:       { type:String, default:'' },
    active:    { type:Boolean, default:true }
}, { _id:false });

const productSchema = new mongoose.Schema({
    name:          { type:String, required:true, trim:true },
    price:         { type:Number, required:true, min:0 },
    originalPrice: { type:Number, default:null },
    category:      { type:String, required:true, enum:['yarn','kit','hook','Toy','Accessories','Keychains','flower'] },
    stock:         { type:Number, required:true, default:0, min:0 },
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
    variants:      { type:[variantSchema], default:[] },
    createdAt:     { type:Date, default:Date.now },
    updatedAt:     { type:Date, default:Date.now }
});
productSchema.index({ category:1, active:1 });
productSchema.index({ name:'text', desc:'text', tags:'text' });

productSchema.pre('save', function(next) {
    if (this.variants && this.variants.length) {
        const activeVariants = this.variants.filter(v => v.active);
        if (activeVariants.length) {
            this.price = Math.min(...activeVariants.map(v => v.price));
            this.stock = activeVariants.reduce((sum, v) => sum + v.stock, 0);
        } else {
            this.stock = 0;
        }
    }
    next();
});

const savedAddressSchema = new mongoose.Schema({
    addressId: { type:String, required:true },
    label:     { type:String, default:'Home' },
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
    savedAddresses: { type:[savedAddressSchema], default:[] },
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
    userId:      { type:mongoose.Schema.Types.ObjectId, ref:'User', default:null },
    guestEmail:  { type:String, default:'', lowercase:true, trim:true },
    guestPhone:  { type:String, default:'', trim:true },
    isGuestOrder:{ type:Boolean, default:false },
    id:          { type:String, required:true, unique:true },
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
    deliveryDays:{ type:Number, default:2 },
    createdAt:   { type:Date, default:Date.now }
});
orderSchema.index({ userId:1, createdAt:-1 });
orderSchema.index({ guestEmail:1, createdAt:-1 });
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
    fileUrl:   { type:String, default:'' },
    driveUrl:  { type:String, default:'' },
    videoUrl:  { type:String, default:'' },
    videoData: { type:String, default:'' },
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
    commissionId: { type:String, required:true, unique:true },
    type:         { type:String, required:true, trim:true },
    name:         { type:String, required:true, trim:true },
    phone:        { type:String, required:true, trim:true },
    email:        { type:String, required:true, trim:true },
    desc:         { type:String, required:true, trim:true },
    budget:       { type:String, default:'' },
    attachment:   { type:String, default:'' },
    attachName:   { type:String, default:'' },
    status:       { type:String, default:'New', enum:['New','Quoted','Accepted','Converting','In Progress','Completed','Converted','Cancelled'] },
    quotedPrice:  { type:Number, default:null },
    proposedBy:   { type:String, default:null, enum:[null,'admin','user'] },
    adminApproved:{ type:Boolean, default:false },
    userApproved: { type:Boolean, default:false },
    negotiationLog: [{
        by:      { type:String, enum:['admin','user'] },
        price:   Number,
        message: { type:String, default:'' },
        at:      { type:Date, default:Date.now }
    }],
    adminNote:    { type:String, default:'' },
    internalNote: { type:String, default:'' },
    completedAt:  { type:Date, default:null },
    linkedOrderId:{ type:String, default:null },
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
// Since all DNS lookups are now forced to IPv4 (see top of file), nodemailer
// will never attempt an IPv6 connection. No custom lookup hack is needed.

const sgTransport = require('nodemailer-sendgrid-transport');

let mailer = null;
let mailerStatus = { configured: false, ok: null, error: null, checkedAt: null, transport: null };

function _initMailer() {
    if (!process.env.SENDGRID_API_KEY) {
        console.warn('⚠️  SENDGRID_API_KEY not set – emails disabled.');
        mailerStatus = { configured:false, ok:false, error:'SENDGRID_API_KEY missing', checkedAt:new Date(), transport:null };
        return;
    }

    mailer = nodemailer.createTransport(sgTransport({
        auth: { api_key: process.env.SENDGRID_API_KEY }
    }));
    mailerStatus.configured = true;
    mailerStatus.transport = 'SendGrid (HTTPS API)';

    mailer.verify(err => {
        mailerStatus.checkedAt = new Date();
        if (err) {
            mailerStatus.ok = false;
            mailerStatus.error = err.message;
            console.warn('⚠️  Email transport error:', err.message);
        } else {
            mailerStatus.ok = true;
            mailerStatus.error = null;
            console.log('✅ Email ready – SendGrid via HTTPS');
        }
    });
}
_initMailer();

const EMAIL_FROM_ADDRESS = process.env.EMAIL_FROM || 'noreply@design-den-studio.vercel.app';

async function sendMail(to, subject, html) {
    if (!mailer) {
        await EmailLog.create({ to, subject, status:'failed', error:'Mailer not configured (SENDGRID_API_KEY missing)' }).catch(()=>{});
        return;
    }
    try {
        await mailer.sendMail({
            from: `"Design Den 🧶" <${EMAIL_FROM_ADDRESS}>`,
            to,
            subject,
            html
        });
        console.log(`📧 Email sent to ${to}`);
        await EmailLog.create({ to, subject, status:'sent' }).catch(()=>{});
    } catch (err) {
        console.warn(`⚠️  Email to ${to} failed:`, err.message);
        await EmailLog.create({ to, subject, status:'failed', error: err.message }).catch(()=>{});
    }
}

// ─── Email templates ──────────────────────────────────────────────────────────
function emailWrap(body) {
    return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Design Den</title></head>
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
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="display:inline-table;background:linear-gradient(135deg,rgba(212,116,140,0.12),rgba(139,50,82,0.08));border:1.5px dashed rgba(212,116,140,0.4);border-radius:999px;margin-bottom:28px;">
        <tr>
          <td style="padding:10px 8px 10px 24px;font-size:0.8rem;white-space:nowrap;">🎀</td>
          <td style="padding:10px 8px;font-size:0.65rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#D4748C;white-space:nowrap;">Welcome to the Family</td>
          <td style="padding:10px 24px 10px 8px;font-size:0.8rem;white-space:nowrap;">🎀</td>
        </tr>
      </table>
      <h1 style="font-family:Georgia,serif;font-size:2.2rem;font-weight:700;color:#3D1A0E;margin:0 0 10px;line-height:1.2;">Hi ${name}! 👋</h1>
      <p style="color:rgba(61,26,14,0.65);font-size:1rem;line-height:1.75;margin:0 0 8px;">We're so thrilled to have you join the <strong style="color:#3D1A0E;">Design Den</strong> family!</p>
      <p style="color:rgba(61,26,14,0.55);font-size:0.9rem;line-height:1.7;margin:0;">Whether you're a seasoned crafter or just picking up your first hook, you've found the right place.</p>
    </div>

    <p style="color:rgba(61,26,14,0.6);font-size:0.88rem;line-height:1.75;margin:0 0 28px;">From hand-dyed yarns and ergonomic hook sets to complete amigurumi kits and step-by-step patterns — everything you need to create something <em style="color:#8B3252;">beautiful</em> is right here.</p>

    <div style="background:linear-gradient(135deg,#FFF6EE,#FAE8D0);border:2px dashed rgba(212,116,140,0.35);border-radius:20px;padding:28px 32px;text-align:center;margin-bottom:32px;">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="display:inline-table;margin-bottom:14px;">
        <tr>
          <td style="font-size:0.65rem;padding-right:6px;">🎁</td>
          <td style="font-size:0.65rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#D4748C;white-space:nowrap;">Your Welcome Gift</td>
        </tr>
      </table>
      <div style="font-family:Georgia,serif;font-size:2.4rem;font-weight:700;letter-spacing:6px;color:#3D1A0E;margin-bottom:10px;">WELCOME10</div>
      <p style="font-size:0.88rem;font-weight:700;color:#3D1A0E;margin:0 0 6px;">10% off your first order — no minimum spend</p>
      <p style="font-size:0.72rem;color:rgba(61,26,14,0.45);margin:0;">Apply at checkout · Valid on any order</p>
    </div>

    <div style="text-align:center;margin-bottom:32px;">
      <a href="${STORE_URL}" style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;text-decoration:none;padding:15px 40px;border-radius:999px;font-weight:800;font-size:0.82rem;letter-spacing:2px;text-transform:uppercase;box-shadow:0 8px 24px rgba(139,50,82,0.25);">START SHOPPING ✦</a>
    </div>

    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="border-top:1px solid rgba(212,116,140,0.15);padding-top:24px;margin-top:4px;">
      <tr>
        <td width="33.33%" align="center" style="text-align:center;padding:0 12px;">
          <div style="font-size:1.6rem;margin-bottom:8px;">🎨</div>
          <div style="font-size:0.72rem;font-weight:800;color:#3D1A0E;margin-bottom:4px;">Hand-Dyed Yarns</div>
          <div style="font-size:0.66rem;color:rgba(61,26,14,0.5);">Premium &amp; vibrant</div>
        </td>
        <td width="33.33%" align="center" style="text-align:center;padding:0 12px;border-left:1px solid rgba(212,116,140,0.12);border-right:1px solid rgba(212,116,140,0.12);">
          <div style="font-size:1.6rem;margin-bottom:8px;">🚚</div>
          <div style="font-size:0.72rem;font-weight:800;color:#3D1A0E;margin-bottom:4px;">Free Shipping</div>
          <div style="font-size:0.66rem;color:rgba(61,26,14,0.5);">On orders over ₹999</div>
        </td>
        <td width="33.33%" align="center" style="text-align:center;padding:0 12px;">
          <div style="font-size:1.6rem;margin-bottom:8px;">📜</div>
          <div style="font-size:0.72rem;font-weight:800;color:#3D1A0E;margin-bottom:4px;">Free Patterns</div>
          <div style="font-size:0.66rem;color:rgba(61,26,14,0.5);">For every skill level</div>
        </td>
      </tr>
    </table>

    <div style="text-align:center;margin-top:28px;padding-top:20px;border-top:1px solid rgba(212,116,140,0.1);">
      <p style="font-size:0.82rem;color:rgba(61,26,14,0.55);margin:0 0 4px;">With yarn love,</p>
      <p style="font-family:Georgia,serif;font-size:1.1rem;font-weight:700;color:#D4748C;margin:0;">— The Design Den Team 🧶</p>
    </div>`);
}

// ... (all other email template functions remain unchanged: patternDeliveryEmail, commissionConfirmEmail, commissionStatusEmail, commissionNegotiationEmail, commissionConvertedEmail, orderStatusEmail, orderConfirmEmail)

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
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:20px;background:#F7EDE6;border-radius:14px;">
      <tr>
        ${p.img ? `<td width="72" valign="middle" style="padding:14px 0 14px 14px;"><img src="${p.img}" width="72" height="72" style="display:block;width:72px;height:72px;border-radius:10px;object-fit:cover;" alt="${p.name}"></td>` : ''}
        <td valign="middle" style="padding:14px;${p.img ? '' : 'padding-left:14px;'}">
          <div style="font-family:Georgia,serif;font-size:1.1rem;font-weight:700;color:#3D1A0E;">${p.name}</div>
          <div style="font-size:0.72rem;color:rgba(61,26,14,0.5);margin-top:2px;">${p.level} · ${p.time||'Self-paced'}</div>
          ${isFree ? '<div style="font-size:0.72rem;font-weight:800;color:#7DAA8A;margin-top:4px;">FREE PATTERN</div>' : `<div style="font-size:0.72rem;font-weight:800;color:#D4A04A;margin-top:4px;">₹${p.price} — PURCHASED ✓</div>`}
        </td>
      </tr>
    </table>
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
    if (!mailer) { await EmailLog.create({ to, subject, status:'failed', error:'Mailer not configured' }).catch(()=>{}); return; }
    try {
        const mailOpts = { from:`"Design Den 🧶" <${EMAIL_FROM_ADDRESS}>`, to, subject, html };
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
        'Accepted':    { icon:'✅', title:'Quote Accepted',            msg:'Thanks for accepting the quote! Complete payment to confirm your order.' },
        'In Progress': { icon:'🔨', title:'Work Has Begun!',          msg:'Great news — our team has started working on your commission!' },
        'Completed':   { icon:'🎉', title:'Your Commission is Ready!', msg:'Your custom piece is complete! We\'ll be in touch shortly.' },
        'Converted':   { icon:'🎉', title:'Order Confirmed!',          msg:'Your payment was received — your commission is now a confirmed order.' },
        'Cancelled':   { icon:'❌', title:'Commission Cancelled',       msg:'Your commission has been cancelled.' },
    };
    const info = statusMsg[c.status] || { icon:'🔔', title:'Commission Update', msg:'Your commission status has been updated.' };
    return emailWrap(`
    <div style="text-align:center;margin-bottom:28px;">
      <div style="font-size:3rem;margin-bottom:12px;">${info.icon}</div>
      <h2 style="font-family:Georgia,serif;font-size:1.8rem;color:#3D1A0E;margin:0 0 8px;">${info.title}</h2>
      <p style="color:rgba(61,26,14,0.55);margin:0;font-size:0.9rem;">${info.msg}</p>
    </div>
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#F7EDE6;border-radius:16px;margin-bottom:20px;">
      <tr>
        <td style="padding:20px 24px;" align="left"><div style="font-size:0.6rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#D4748C;margin-bottom:4px;">Commission ID</div><div style="font-family:Georgia,serif;font-size:1.3rem;font-weight:700;color:#3D1A0E;">${c.commissionId}</div></td>
        <td style="padding:20px 24px;" align="right" valign="top"><span style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;border-radius:99px;padding:8px 18px;font-size:0.72rem;font-weight:800;letter-spacing:1px;white-space:nowrap;">${c.status.toUpperCase()}</span></td>
      </tr>
    </table>
    ${c.quotedPrice?`<div style="background:white;border:2px dashed rgba(212,160,74,0.4);border-radius:14px;padding:16px 20px;margin-bottom:20px;text-align:center;"><div style="font-size:0.72rem;font-weight:800;color:rgba(61,26,14,0.45);margin-bottom:6px;">Quoted Price</div><div style="font-family:Georgia,serif;font-size:2rem;font-weight:700;color:#3D1A0E;">₹${c.quotedPrice.toLocaleString('en-IN')}</div></div>`:''}
    ${c.adminNote?`<div style="background:white;border-left:3px solid #D4748C;border-radius:0 14px 14px 0;padding:16px 20px;margin-bottom:20px;"><div style="font-size:0.6rem;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#D4748C;margin-bottom:8px;">📌 Message from Design Den</div><div style="font-size:0.85rem;color:rgba(61,26,14,0.7);line-height:1.65;">${c.adminNote}</div></div>`:''}
    <div style="text-align:center;margin-top:20px;">
      <a href="${STORE_URL}/#custom" style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;text-decoration:none;padding:13px 32px;border-radius:999px;font-weight:800;font-size:0.8rem;letter-spacing:2px;text-transform:uppercase;">Track Commission →</a>
    </div>`)
}

function commissionNegotiationEmail(c, toRole) {
    const last = c.negotiationLog[c.negotiationLog.length - 1];
    const otherRole = toRole === 'admin' ? 'user' : 'admin';
    const otherName = otherRole === 'admin' ? 'Design Den' : c.name;
    const isApproval = last && last.by === otherRole && c.negotiationLog.length > 1
        && c.negotiationLog[c.negotiationLog.length - 2]?.price === last.price;
    const bothApproved = c.adminApproved && c.userApproved;
    let icon, title, msg;
    if (bothApproved) {
        icon = '🎉'; title = 'Price Agreed!';
        msg = toRole === 'user'
            ? `You and Design Den have agreed on ₹${c.quotedPrice.toLocaleString('en-IN')} — complete payment to confirm your order.`
            : `You and ${c.name} have agreed on ₹${c.quotedPrice.toLocaleString('en-IN')}. Once they pay, this becomes a tracked order automatically.`;
    } else if (isApproval) {
        icon = '👍'; title = `${otherName} Approved Your Price`;
        msg = `₹${c.quotedPrice.toLocaleString('en-IN')} has been approved by ${otherName}.` + (toRole === 'user' ? ' Approve it too to move forward with payment.' : ' Waiting on your approval to proceed.');
    } else {
        icon = '💬'; title = `${otherName} Proposed a New Price`;
        msg = `${otherName} suggested ₹${c.quotedPrice.toLocaleString('en-IN')}${last?.message ? ' — "' + last.message + '"' : ''}.`;
    }
    return emailWrap(`
    <div style="text-align:center;margin-bottom:28px;">
      <div style="font-size:3rem;margin-bottom:12px;">${icon}</div>
      <h2 style="font-family:Georgia,serif;font-size:1.8rem;color:#3D1A0E;margin:0 0 8px;">${title}</h2>
      <p style="color:rgba(61,26,14,0.55);margin:0;font-size:0.9rem;">${msg}</p>
    </div>
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#F7EDE6;border-radius:16px;margin-bottom:20px;">
      <tr>
        <td style="padding:20px 24px;" align="left"><div style="font-size:0.6rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#D4748C;margin-bottom:4px;">Commission ID</div><div style="font-family:Georgia,serif;font-size:1.3rem;font-weight:700;color:#3D1A0E;">${c.commissionId}</div></td>
        <td style="padding:20px 24px;" align="right" valign="top"><div style="font-size:0.6rem;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:rgba(61,26,14,0.4);margin-bottom:4px;">Current Price</div><div style="font-family:Georgia,serif;font-size:1.3rem;font-weight:700;color:#3D1A0E;">₹${c.quotedPrice.toLocaleString('en-IN')}</div></td>
      </tr>
    </table>
    <div style="text-align:center;margin-top:20px;">
      ${toRole === 'admin'
        ? `<a href="${STORE_URL}" style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;text-decoration:none;padding:13px 32px;border-radius:999px;font-weight:800;font-size:0.8rem;letter-spacing:2px;text-transform:uppercase;">Open Admin Panel →</a>`
        : `<a href="${STORE_URL}/#custom" style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;text-decoration:none;padding:13px 32px;border-radius:999px;font-weight:800;font-size:0.8rem;letter-spacing:2px;text-transform:uppercase;">Review &amp; Respond →</a>`}
    </div>`)
}

function commissionConvertedEmail(c, order) {
    return emailWrap(`
    <div style="text-align:center;margin-bottom:28px;">
      <div style="font-size:3rem;margin-bottom:12px;">🎉</div>
      <h2 style="font-family:Georgia,serif;font-size:1.8rem;color:#3D1A0E;margin:0 0 8px;">Payment Received — Order Confirmed!</h2>
      <p style="color:rgba(61,26,14,0.55);margin:0;font-size:0.9rem;">Your custom commission is now a confirmed order and will be tracked through to delivery.</p>
    </div>
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#F7EDE6;border-radius:16px;margin-bottom:20px;">
      <tr>
        <td style="padding:20px 24px 6px;" align="left"><div style="font-size:0.6rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#D4748C;margin-bottom:4px;">Order ID</div><div style="font-family:Georgia,serif;font-size:1.3rem;font-weight:700;color:#3D1A0E;">${order.id}</div></td>
        <td style="padding:20px 24px 6px;" align="right" valign="top"><span style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;border-radius:99px;padding:8px 18px;font-size:0.72rem;font-weight:800;letter-spacing:1px;white-space:nowrap;">PLACED</span></td>
      </tr>
      <tr>
        <td colspan="2" style="padding:0 24px 20px;font-size:0.72rem;color:rgba(61,26,14,0.4);">From Commission ${c.commissionId} — ${c.type}</td>
      </tr>
    </table>
    <div style="background:white;border:2px dashed rgba(212,160,74,0.4);border-radius:14px;padding:16px 20px;margin-bottom:20px;text-align:center;">
      <div style="font-size:0.72rem;font-weight:800;color:rgba(61,26,14,0.45);margin-bottom:6px;">Amount Paid</div>
      <div style="font-family:Georgia,serif;font-size:2rem;font-weight:700;color:#3D1A0E;">₹${order.total.toLocaleString('en-IN')}</div>
    </div>
    <div style="text-align:center;margin-top:20px;">
      <a href="${STORE_URL}/#custom" style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;text-decoration:none;padding:13px 32px;border-radius:999px;font-weight:800;font-size:0.8rem;letter-spacing:2px;text-transform:uppercase;">Track Your Order →</a>
    </div>`)
}

function orderStatusEmail(o) {
    const statusMsg = {
        'Confirmed':        { icon:'✅', title:'Order Confirmed!',       msg:'We\'ve confirmed your order and are getting it ready.' },
        'Processing':       { icon:'🧶', title:'Your Order is Being Made!', msg:'Our artisans are working on your order right now.' },
        'Shipped':          { icon:'📦', title:'Your Order Has Shipped!', msg:'Your order is on its way to you.' },
        'Out for Delivery': { icon:'🚚', title:'Out for Delivery!',       msg:'Your order will arrive today — keep your phone handy.' },
        'Delivered':        { icon:'🎉', title:'Delivered!',              msg:'Your order has been delivered. We hope you love it!' },
        'Cancelled':        { icon:'❌', title:'Order Cancelled',         msg:'Your order has been cancelled.' },
    };
    const info = statusMsg[o.status] || { icon:'🔔', title:'Order Update', msg:'Your order status has been updated.' };
    return emailWrap(`
    <div style="text-align:center;margin-bottom:28px;">
      <div style="font-size:3rem;margin-bottom:12px;">${info.icon}</div>
      <h2 style="font-family:Georgia,serif;font-size:1.8rem;color:#3D1A0E;margin:0 0 8px;">${info.title}</h2>
      <p style="color:rgba(61,26,14,0.55);margin:0;font-size:0.9rem;">${info.msg}</p>
    </div>
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#F7EDE6;border-radius:16px;margin-bottom:20px;">
      <tr>
        <td style="padding:20px 24px;" align="left"><div style="font-size:0.6rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#D4748C;margin-bottom:4px;">Order ID</div><div style="font-family:Georgia,serif;font-size:1.3rem;font-weight:700;color:#3D1A0E;">${o.id}</div></td>
        <td style="padding:20px 24px;" align="right" valign="top"><span style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;border-radius:99px;padding:8px 18px;font-size:0.72rem;font-weight:800;letter-spacing:1px;white-space:nowrap;">${o.status.toUpperCase()}</span></td>
      </tr>
    </table>
    ${o.adminNote?`<div style="background:white;border-left:3px solid #D4748C;border-radius:0 14px 14px 0;padding:16px 20px;margin-bottom:20px;"><div style="font-size:0.6rem;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#D4748C;margin-bottom:8px;">📌 Note from Design Den</div><div style="font-size:0.85rem;color:rgba(61,26,14,0.7);line-height:1.65;">${o.adminNote}</div></div>`:''}
    <div style="text-align:center;margin-top:20px;">
      <a href="${STORE_URL}/#track" style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;text-decoration:none;padding:13px 32px;border-radius:999px;font-weight:800;font-size:0.8rem;letter-spacing:2px;text-transform:uppercase;">Track Your Order →</a>
    </div>`)
}

function orderConfirmEmail(order, customerName) {
    const isCOD = order.payment && order.payment.method === 'Cash on Delivery';
    const itemRows = Array.isArray(order.items) ? order.items.map(item => {
        const variantLabel = item.variantLabel ? ` — ${item.variantLabel}` : '';
        return `<tr>
          <td style="padding:10px 0;border-bottom:1px solid rgba(212,116,140,0.1);font-size:0.82rem;color:#3D1A0E;">${item.name||'Item'}${variantLabel}</td>
          <td style="padding:10px 0;border-bottom:1px solid rgba(212,116,140,0.1);font-size:0.82rem;color:rgba(61,26,14,0.55);text-align:center;">${item.qty||1}</td>
          <td style="padding:10px 0;border-bottom:1px solid rgba(212,116,140,0.1);font-size:0.82rem;color:#3D1A0E;text-align:right;">₹${((item.price||0)*(item.qty||1)).toLocaleString('en-IN')}</td>
        </tr>`;
    }).join('') : '';

    return emailWrap(`
    <div style="text-align:center;margin-bottom:28px;">
      <div style="font-size:3rem;margin-bottom:12px;">🎉</div>
      <h2 style="font-family:Georgia,serif;font-size:1.8rem;color:#3D1A0E;margin:0 0 8px;">Order Placed Successfully!</h2>
      <p style="color:rgba(61,26,14,0.55);margin:0;font-size:0.9rem;">${customerName ? `Hi ${customerName}! ` : ''}Thank you for your order — we're on it! 🧶</p>
    </div>
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#F7EDE6;border-radius:16px;margin-bottom:20px;">
      <tr>
        <td style="padding:20px 24px;" align="left">
          <div style="font-size:0.6rem;font-weight:800;letter-spacing:3px;text-transform:uppercase;color:#D4748C;margin-bottom:4px;">Order ID</div>
          <div style="font-family:Georgia,serif;font-size:1.3rem;font-weight:700;color:#3D1A0E;">${order.id}</div>
          <div style="font-size:0.72rem;color:rgba(61,26,14,0.4);margin-top:4px;">${order.date || ''}</div>
        </td>
        <td style="padding:20px 24px;" align="right" valign="top">
          <span style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;border-radius:99px;padding:8px 18px;font-size:0.72rem;font-weight:800;letter-spacing:1px;white-space:nowrap;">PLACED ✓</span>
        </td>
      </tr>
    </table>

    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:20px;">
      <tr>
        <th style="padding:0 0 8px;font-size:0.65rem;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:rgba(61,26,14,0.4);text-align:left;">Item</th>
        <th style="padding:0 0 8px;font-size:0.65rem;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:rgba(61,26,14,0.4);text-align:center;">Qty</th>
        <th style="padding:0 0 8px;font-size:0.65rem;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:rgba(61,26,14,0.4);text-align:right;">Price</th>
      </tr>
      ${itemRows}
    </table>

    <div style="background:#F7EDE6;border-radius:14px;padding:16px 20px;margin-bottom:24px;">
      ${order.discount > 0 ? `<div style="display:flex;justify-content:space-between;margin-bottom:6px;"><span style="font-size:0.8rem;color:rgba(61,26,14,0.55);">Subtotal</span><span style="font-size:0.8rem;color:#3D1A0E;">₹${(order.total + order.discount - order.shipping).toLocaleString('en-IN')}</span></div><div style="display:flex;justify-content:space-between;margin-bottom:6px;"><span style="font-size:0.8rem;color:#7DAA8A;">Discount</span><span style="font-size:0.8rem;color:#7DAA8A;">−₹${order.discount.toLocaleString('en-IN')}</span></div>` : ''}
      <div style="display:flex;justify-content:space-between;margin-bottom:6px;"><span style="font-size:0.8rem;color:rgba(61,26,14,0.55);">Shipping</span><span style="font-size:0.8rem;color:#3D1A0E;">${order.shipping > 0 ? `₹${order.shipping.toLocaleString('en-IN')}` : 'FREE 🎁'}</span></div>
      <div style="border-top:1px solid rgba(212,116,140,0.2);margin-top:8px;padding-top:8px;display:flex;justify-content:space-between;"><span style="font-size:0.95rem;font-weight:800;color:#3D1A0E;">Total</span><span style="font-family:Georgia,serif;font-size:1.1rem;font-weight:700;color:#3D1A0E;">₹${order.total.toLocaleString('en-IN')}</span></div>
      ${isCOD ? `<div style="margin-top:10px;padding:8px 12px;background:rgba(212,116,140,0.1);border-radius:8px;font-size:0.75rem;color:rgba(61,26,14,0.6);text-align:center;">💵 Cash on Delivery — please keep ₹${order.total.toLocaleString('en-IN')} ready at the time of delivery.</div>` : `<div style="margin-top:10px;padding:8px 12px;background:rgba(125,170,138,0.12);border-radius:8px;font-size:0.75rem;color:rgba(61,26,14,0.6);text-align:center;">✅ Payment received online</div>`}
    </div>

    ${order.address ? `<div style="border:1.5px dashed rgba(212,116,140,0.3);border-radius:14px;padding:16px 20px;margin-bottom:24px;">
      <div style="font-size:0.6rem;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#D4748C;margin-bottom:8px;">📍 Delivery Address</div>
      <div style="font-size:0.82rem;color:#3D1A0E;line-height:1.7;">${order.address.name||''}<br>${order.address.line1||''}${order.address.line2 ? ', '+order.address.line2 : ''}<br>${order.address.city||''}${order.address.state ? ', '+order.address.state : ''}${order.address.pin ? ' — '+order.address.pin : ''}</div>
    </div>` : ''}

    <div style="text-align:center;margin-bottom:28px;">
      <a href="${STORE_URL}/#track" style="display:inline-block;background:linear-gradient(135deg,#D4748C,#8B3252);color:white;text-decoration:none;padding:14px 36px;border-radius:999px;font-weight:800;font-size:0.82rem;letter-spacing:2px;text-transform:uppercase;box-shadow:0 8px 24px rgba(139,50,82,0.25);">TRACK YOUR ORDER →</a>
      <div style="font-size:0.68rem;color:rgba(61,26,14,0.35);margin-top:8px;">Use your Order ID: <strong>${order.id}</strong></div>
    </div>
    <div style="text-align:center;padding-top:20px;border-top:1px solid rgba(212,116,140,0.1);">
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

function optionalAuth(req, res, next) {
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer ')) { req.user = null; return next(); }
    try {
        const payload = jwt.verify(h.slice(7), process.env.JWT_SECRET);
        if (payload.isAdmin) return res.status(403).json({ message:'Use user token' });
        req.user = payload;
    } catch { req.user = null; }
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
        if (minPrice || maxPrice) {
            q.price = {};
            if (minPrice) q.price.$gte = parseFloat(minPrice);
            if (maxPrice) q.price.$lte = parseFloat(maxPrice);
        }
        if (material) {
            const materials = String(material).split(',').map(m=>m.trim()).filter(Boolean);
            if (materials.length) q.material = { $in: materials.map(m => new RegExp(`^${m}$`,'i')) };
        }
        if (inStock === 'true') q.stock = { $gt: 0 };

        let query = Product.find(q).select('-__v');
        if (sort === 'price_asc')       query = query.sort({ price:1 });
        else if (sort === 'price_desc') query = query.sort({ price:-1 });
        else if (sort === 'rating')     query = query.sort({ rating:-1 });
        else query = query.sort({ createdAt:-1 });
        res.json({ products: await query });
    } catch(err) { console.error('[GET /products]',err); res.status(500).json({ message:'Failed to fetch products' }); }
});

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

app.post('/api/patterns/:id/purchase-order', async (req,res) => {
    try {
        const p = await Pattern.findById(req.params.id);
        if (!p || p.status !== 'Published') return res.status(404).json({ message:'Pattern not found' });
        if (!p.price || p.price <= 0) return res.status(400).json({ message:'This pattern is free. Use the download endpoint.' });
        const { email } = req.body;
        const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
        if (!email || !emailRx.test(email.trim())) return res.status(400).json({ message:'Please enter your email address.' });
        
        const shortTimestamp = Date.now().toString(36);
        const shortPatternId = p._id.toString().slice(-6);
        const receiptStr = `PAT_${shortTimestamp}_${shortPatternId}`;
        
        const rzpOrder = await razorpay.orders.create({
            amount: Math.round(p.price * 100),
            currency: 'INR',
            receipt: receiptStr,
            notes: { patternId: p._id.toString(), patternName: p.name, buyerEmail: email.trim().toLowerCase() }
        });
        res.json({ orderId: rzpOrder.id, amount: rzpOrder.amount, key: process.env.RAZORPAY_KEY_ID, patternName: p.name });
    } catch(err) { console.error('[pattern/purchase-order]',err); res.status(500).json({ message:'Payment order creation failed: '+err.message }); }
});

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

        if (attachment) {
            const ALLOWED_MIME = ['image/jpeg','image/png','image/webp','image/gif','application/pdf'];
            const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;
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

async function attachLinkedOrderStatus(commissionOrList) {
    const list = Array.isArray(commissionOrList) ? commissionOrList : [commissionOrList];
    const orderIds = list.map(c => c.linkedOrderId).filter(Boolean);
    if (!orderIds.length) return commissionOrList;
    const orders = await Order.find({ id: { $in: orderIds } })
        .select('id status date deliveryDays createdAt total');
    const orderMap = new Map(orders.map(o => [o.id, o]));
    for (const c of list) {
        if (c.linkedOrderId && orderMap.has(c.linkedOrderId)) {
            const o = orderMap.get(c.linkedOrderId);
            c._doc.linkedOrder = { id:o.id, status:o.status, date:o.date, deliveryDays:o.deliveryDays, total:o.total };
        }
    }
    return commissionOrList;
}

app.get('/api/commissions/track/:commissionId', async (req,res) => {
    try {
        const c = await Commission.findOne({ commissionId: req.params.commissionId.toUpperCase() })
            .select('commissionId type name status adminNote quotedPrice createdAt budget completedAt linkedOrderId proposedBy adminApproved userApproved negotiationLog');
        if (!c) return res.status(404).json({ message:'Commission not found. Please check your ID.' });
        await attachLinkedOrderStatus(c);
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
            .select('commissionId type name status adminNote quotedPrice createdAt budget completedAt linkedOrderId proposedBy adminApproved userApproved negotiationLog');
        await attachLinkedOrderStatus(commissions);
        res.json({ commissions });
    } catch { res.status(500).json({ message:'Error' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  COMMISSION NEGOTIATION & CONVERSION
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/commissions/:commissionId/propose', optionalAuth, async (req,res) => {
    try {
        const { price, message } = req.body;
        const p = Number(price);
        if (!p || p <= 0) return res.status(400).json({ message:'Enter a valid price.' });
        const c = await Commission.findOne({ commissionId: req.params.commissionId.toUpperCase() });
        if (!c) return res.status(404).json({ message:'Commission not found.' });
        if (c.status === 'Converted') return res.status(400).json({ message:'This commission has already been paid for and converted into an order.' });
        if (!c.quotedPrice) return res.status(400).json({ message:'Design Den hasn\'t sent an initial quote yet — please wait for that first.' });
        c.quotedPrice = p;
        c.proposedBy = 'user';
        c.userApproved = true;
        c.adminApproved = false;
        c.negotiationLog.push({ by:'user', price:p, message: (message||'').trim() });
        await c.save();
        if (ADMIN_NOTIFY_EMAIL) sendMail(ADMIN_NOTIFY_EMAIL, `${c.name} Countered — ${c.commissionId} 💬`, commissionNegotiationEmail(c, 'admin'));
        res.json({ commission:c });
    } catch(e) { res.status(400).json({ message:e.message }); }
});

app.post('/api/commissions/:commissionId/approve-quote', optionalAuth, async (req,res) => {
    try {
        const c = await Commission.findOne({ commissionId: req.params.commissionId.toUpperCase() });
        if (!c) return res.status(404).json({ message:'Commission not found.' });
        if (!c.quotedPrice) return res.status(400).json({ message:'There is no price to approve yet.' });
        if (c.userApproved) return res.json({ commission:c });
        c.userApproved = true;
        c.negotiationLog.push({ by:'user', price:c.quotedPrice, message:'Approved' });
        await c.save();
        if (ADMIN_NOTIFY_EMAIL) sendMail(ADMIN_NOTIFY_EMAIL, `${c.name} Approved the Price — ${c.commissionId} 👍`, commissionNegotiationEmail(c, 'admin'));
        res.json({ commission:c });
    } catch(e) { res.status(400).json({ message:e.message }); }
});

app.post('/api/commissions/:commissionId/accept', optionalAuth, async (req,res) => {
    try {
        const c = await Commission.findOne({ commissionId: req.params.commissionId.toUpperCase() });
        if (!c) return res.status(404).json({ message:'Commission not found.' });
        if (!['Quoted','Accepted'].includes(c.status)) return res.status(400).json({ message:'This commission does not have an active quote to accept.' });
        if (!c.quotedPrice || c.quotedPrice <= 0) return res.status(400).json({ message:'No quoted price has been set yet.' });
        if (!c.adminApproved || !c.userApproved) {
            return res.status(400).json({ message:'Both you and Design Den need to approve the current price before payment can start.' });
        }
        if (c.status !== 'Accepted') { c.status = 'Accepted'; await c.save(); }
        const rzpOrder = await razorpay.orders.create({
            amount: Math.round(c.quotedPrice * 100),
            currency: 'INR',
            receipt: `DDC_${Date.now().toString(36)}`.slice(0, 40)
        });
        res.json({ orderId: rzpOrder.id, key: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder', amount: c.quotedPrice });
    } catch (err) { console.error('[POST /commissions/:id/accept]', err); res.status(500).json({ message:'Could not start payment. Please try again.' }); }
});

app.post('/api/commissions/:commissionId/pay/verify', optionalAuth, async (req,res) => {
    try {
        const commIdUpper = req.params.commissionId.toUpperCase();
        const c = await Commission.findOne({ commissionId: commIdUpper });
        if (!c) return res.status(404).json({ message:'Commission not found.' });
        if (c.status === 'Converted' && c.linkedOrderId) {
            const existing = await Order.findOne({ id: c.linkedOrderId });
            return res.json({ success:true, order: existing });
        }
        if (c.status !== 'Accepted') return res.status(400).json({ message:'This commission is not awaiting payment.' });

        const { razorpay_order_id, razorpay_payment_id, razorpay_signature, address, guestEmail, guestPhone } = req.body;
        const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(razorpay_order_id + '|' + razorpay_payment_id).digest('hex');
        if (expected !== razorpay_signature) return res.status(400).json({ message:'Payment verification failed. Please contact support.' });
        if (!address || !address.line1 || !address.city || !address.pin) return res.status(400).json({ message:'A delivery address is required.' });

        const isGuest = !req.user;
        if (isGuest) {
            const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
            if (!guestEmail || !emailRx.test(String(guestEmail).trim().toLowerCase())) {
                return res.status(400).json({ message:'A valid email is required.' });
            }
        }

        const claimed = await Commission.findOneAndUpdate(
            { commissionId: commIdUpper, status: 'Accepted' },
            { status: 'Converting' },
            { new: true }
        );
        if (!claimed) {
            const recheck = await Commission.findOne({ commissionId: commIdUpper });
            if (recheck && recheck.status === 'Converted' && recheck.linkedOrderId) {
                const existing = await Order.findOne({ id: recheck.linkedOrderId });
                return res.json({ success:true, order: existing });
            }
            return res.status(409).json({ message:'This commission is already being processed. Please refresh and try again.' });
        }

        const shipDaysSetting = await Settings.findOne({ key: 'shipping.days' });
        const defaultDeliveryDays = shipDaysSetting ? parseInt(shipDaysSetting.value, 10) || 2 : 2;
        const orderId = `DD-${Date.now().toString(36).toUpperCase()}${Math.random().toString(36).substring(2, 5).toUpperCase()}`;

        let order;
        try {
            order = await Order.create({
                userId: req.user ? req.user.id : null,
                guestEmail: isGuest ? String(guestEmail).trim().toLowerCase() : '',
                guestPhone: isGuest ? String(guestPhone || '').trim() : '',
                isGuestOrder: isGuest,
                id: orderId,
                items: [{
                    _id: 'commission-' + c.commissionId,
                    name: `Custom Commission — ${c.type}`,
                    price: c.quotedPrice,
                    qty: 1,
                    isCommission: true,
                    commissionId: c.commissionId
                }],
                total: c.quotedPrice,
                shipping: 0,
                discount: 0,
                coupon: null,
                status: 'Placed',
                date: new Date().toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' }),
                address,
                payment: { method:'Online', txnId:razorpay_payment_id, razorpayOrderId:razorpay_order_id },
                deliveryDays: defaultDeliveryDays
            });
        } catch (createErr) {
            await Commission.findOneAndUpdate({ commissionId: commIdUpper, status: 'Converting' }, { status: 'Accepted' });
            throw createErr;
        }

        claimed.status = 'Converted';
        claimed.linkedOrderId = orderId;
        await claimed.save();
        if (req.user) await User.findByIdAndUpdate(req.user.id, { $inc:{ totalSpent:c.quotedPrice, orderCount:1 } });

        sendMail(c.email, `Commission Confirmed & Order Placed — ${orderId} 🎉`, commissionConvertedEmail(c, order));
        res.status(201).json({ success:true, order });
    } catch (err) { console.error('[POST /commissions/:id/pay/verify]', err); res.status(500).json({ message:'Payment succeeded but we could not finalize your order — please contact support with your payment ID.' }); }
});

app.get('/api/user/commissions', auth, async (req,res) => {
    try {
        const user = await User.findById(req.user.id).select('email');
        if (!user) return res.status(404).json({ message:'User not found' });
        const commissions = await Commission.find({ email: user.email })
            .sort({ createdAt:-1 })
            .select('commissionId type name status adminNote quotedPrice createdAt budget completedAt linkedOrderId proposedBy adminApproved userApproved negotiationLog');
        await attachLinkedOrderStatus(commissions);
        res.json({ commissions });
    } catch { res.status(500).json({ message:'Error' }); }
});

// ── Saved addresses ───────────────────────────────────────────────────────────
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
        if (newAddr.isDefault) user.savedAddresses.forEach(a => a.isDefault = false);
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
        if (wasDefault && user.savedAddresses.length) user.savedAddresses[0].isDefault = true;
        await user.save();
        res.json({ addresses: user.savedAddresses });
    } catch { res.status(500).json({ message:'Failed to delete address' }); }
});

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

// Newsletter subscribe (public)
app.post('/api/subscribe', async (req,res) => {
    try {
        const { email } = req.body;
        const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
        if (!email || !emailRx.test(email.trim().toLowerCase())) {
            return res.status(400).json({ message:'Please enter a valid email address' });
        }
        const normalised = email.trim().toLowerCase();
        const existing = await Subscriber.findOne({ email: normalised });
        if (existing) return res.status(409).json({ message:'You\'re already subscribed — thanks!' });
        await Subscriber.create({ email: normalised });
        res.status(201).json({ success:true });
    } catch(err) {
        console.error('[POST /subscribe]', err);
        res.status(500).json({ message:'Subscription failed — please try again.' });
    }
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
    const reserved = [];
    try {
        const { items, status, date, address, payment, coupon, guestEmail, guestPhone } = req.body;
        if (!items || !items.length) return res.status(400).json({ message:'Missing required fields' });

        const isGuest = !req.user;
        if (isGuest) {
            const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
            if (!guestEmail || !emailRx.test(String(guestEmail).trim().toLowerCase())) {
                return res.status(400).json({ message:'A valid email is required to place an order as a guest.' });
            }
        }

        if (payment && payment.method === 'Cash on Delivery') {
            const codSetting = await Settings.findOne({ key: 'shipping.cod' });
            const codEnabled = !codSetting || codSetting.value === 'Yes';
            if (!codEnabled) {
                return res.status(400).json({ message:'Cash on Delivery is currently unavailable. Please pay online to complete your order.' });
            }
        }

        const { subtotal, discount, coupon:appliedCoupon, shipping, total } = await computeTrustedOrderTotals(items, coupon);

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
                if (updated) await updated.save();
            } else {
                updated = await Product.findOneAndUpdate(
                    { _id: pid, stock: { $gte: qty } },
                    { $inc: { stock: -qty }, updatedAt: new Date() },
                    { new: true }
                );
            }

            if (!updated) {
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

        const shipDaysSetting = await Settings.findOne({ key: 'shipping.days' });
        const defaultDeliveryDays = shipDaysSetting ? parseInt(shipDaysSetting.value, 10) || 2 : 2;

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
        if (req.user) await User.findByIdAndUpdate(req.user.id, { $inc:{ totalSpent:total, orderCount:1 } });

        try {
            let toEmail = isGuest ? order.guestEmail : null;
            let customerName = null;
            if (!isGuest && req.user) {
                const u = await User.findById(req.user.id).select('email name');
                if (u) { toEmail = u.email; customerName = u.name; }
            }
            if (toEmail) {
                sendMail(toEmail, `Order Confirmed — ${order.id} 🧶`, orderConfirmEmail(order, customerName));
            }
        } catch (emailErr) {
            console.warn('[POST /orders] confirmation email error:', emailErr.message);
        }

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

app.post('/api/payment/webhook', express.raw({ type:'application/json' }), async (req,res) => {
    try {
        const signature = req.headers['x-razorpay-signature'];
        const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
        if (!secret) { console.warn('⚠️  RAZORPAY_WEBHOOK_SECRET not set — webhook disabled'); return res.status(200).send('ok'); }
        if (!signature) return res.status(400).send('Missing signature');

        const expected = crypto.createHmac('sha256', secret).update(req.body).digest('hex');
        if (expected !== signature) { console.warn('⚠️  Webhook signature mismatch'); return res.status(400).send('Invalid signature'); }

        const event = JSON.parse(req.body.toString('utf8'));
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
        res.status(200).send('ok');
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
app.put('/api/admin/products/:id', adminAuth, async (req,res) => {
    try {
        const p = await Product.findById(req.params.id);
        if (!p) return res.status(404).json({ message:'Not found' });
        Object.assign(p, req.body, { updatedAt:new Date() });
        await p.save();
        res.json({ product:p });
    } catch(e) { res.status(400).json({ message:e.message }); }
});
app.patch('/api/admin/products/:id/stock',   adminAuth, async (req,res) => {
    try {
        const { stock, delta } = req.body;
        const p = await Product.findById(req.params.id);
        if (!p) return res.status(404).json({ message:'Not found' });
        if (p.variants && p.variants.length) {
            return res.status(400).json({ message:'This product has variants — update stock per-variant via PATCH /api/admin/products/:id/variants/:variantId/stock' });
        }
        if (delta!==undefined) p.stock=Math.max(0,p.stock+delta);
        else if (stock!==undefined) p.stock=Math.max(0,stock);
        p.updatedAt=new Date();
        await p.save();
        res.json({ product:p });
    } catch(e) { res.status(400).json({ message:e.message }); }
});
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
        await p.save();
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
        const { status, adminNote, deliveryDays } = req.body;
        const update = { status };
        if (adminNote !== undefined) update.adminNote = adminNote;
        if (deliveryDays !== undefined) update.deliveryDays = deliveryDays;

        const prev = await Order.findOne({ id:req.params.id }).select('status guestEmail userId');
        if (!prev) return res.status(404).json({ message:'Order not found' });

        const order = await Order.findOneAndUpdate({ id:req.params.id }, update, { new:true });

        if (status && status !== prev.status) {
            let toEmail = order.guestEmail;
            if (!toEmail && prev.userId) {
                const u = await User.findById(prev.userId).select('email');
                toEmail = u && u.email;
            }
            if (toEmail) sendMail(toEmail, `Order Update — ${order.id} (${order.status}) 🧶`, orderStatusEmail(order));
        }

        res.json({ order });
    } catch { res.status(500).json({ message:'Failed to update order' }); }
});

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
        const failedEmails   = await EmailLog.countDocuments({ status:'failed' });
        res.json({ products, orders, users, lowStock, outStock, revenue:revenueAgg[0]?.total||0, statusCounts:Object.fromEntries(statusCounts.map(s=>[s._id,s.count])), pendingTestis, newCommissions, failedEmails });
    } catch(err) { console.error('[stats]',err); res.status(500).json({ message:'Failed to fetch stats' }); }
});

app.get('/api/admin/coupons',        adminAuth, async (_,res)   => { try{res.json({coupons:await Coupon.find().sort({createdAt:-1})});}catch{res.status(500).json({message:'Error'});} });
app.post('/api/admin/coupons',       adminAuth, async (req,res) => { try{res.status(201).json({coupon:await Coupon.create(req.body)});}catch(e){res.status(400).json({message:e.message});} });
app.put('/api/admin/coupons/:id',    adminAuth, async (req,res) => { try{const c=await Coupon.findByIdAndUpdate(req.params.id,req.body,{new:true,runValidators:true});if(!c)return res.status(404).json({message:'Not found'});res.json({coupon:c});}catch(e){res.status(400).json({message:e.message});} });
app.delete('/api/admin/coupons/:id', adminAuth, async (req,res) => { try{await Coupon.findByIdAndDelete(req.params.id);res.json({success:true});}catch{res.status(500).json({message:'Error'});} });

app.get('/api/admin/patterns',        adminAuth, async (_,res)   => { try{res.json({patterns:await Pattern.find().sort({createdAt:-1})});}catch{res.status(500).json({message:'Error'});} });
app.post('/api/admin/patterns',       adminAuth, async (req,res) => { try{res.status(201).json({pattern:await Pattern.create(req.body)});}catch(e){res.status(400).json({message:e.message});} });
app.put('/api/admin/patterns/:id',    adminAuth, async (req,res) => { try{const p=await Pattern.findByIdAndUpdate(req.params.id,req.body,{new:true});if(!p)return res.status(404).json({message:'Not found'});res.json({pattern:p});}catch(e){res.status(400).json({message:e.message});} });
app.delete('/api/admin/patterns/:id', adminAuth, async (req,res) => { try{await Pattern.findByIdAndDelete(req.params.id);res.json({success:true});}catch{res.status(500).json({message:'Error'});} });

app.get('/api/admin/testimonials',        adminAuth, async (_,res)   => { try{res.json({testimonials:await Testimonial.find().sort({createdAt:-1})});}catch{res.status(500).json({message:'Error'});} });
app.post('/api/admin/testimonials',       adminAuth, async (req,res) => { try{res.status(201).json({testimonial:await Testimonial.create(req.body)});}catch(e){res.status(400).json({message:e.message});} });
app.put('/api/admin/testimonials/:id',    adminAuth, async (req,res) => { try{const t=await Testimonial.findByIdAndUpdate(req.params.id,req.body,{new:true});if(!t)return res.status(404).json({message:'Not found'});res.json({testimonial:t});}catch(e){res.status(400).json({message:e.message});} });
app.delete('/api/admin/testimonials/:id', adminAuth, async (req,res) => { try{await Testimonial.findByIdAndDelete(req.params.id);res.json({success:true});}catch{res.status(500).json({message:'Error'});} });

app.get('/api/admin/gallery',        adminAuth, async (_,res)   => { try{res.json({images:await Gallery.find().sort({sortOrder:1,createdAt:1})});}catch{res.status(500).json({message:'Error'});} });
app.post('/api/admin/gallery',       adminAuth, async (req,res) => { try{res.status(201).json({image:await Gallery.create(req.body)});}catch(e){res.status(400).json({message:e.message});} });
app.put('/api/admin/gallery/:id',    adminAuth, async (req,res) => { try{const g=await Gallery.findByIdAndUpdate(req.params.id,req.body,{new:true});if(!g)return res.status(404).json({message:'Not found'});res.json({image:g});}catch(e){res.status(400).json({message:e.message});} });
app.delete('/api/admin/gallery/:id', adminAuth, async (req,res) => { try{await Gallery.findByIdAndDelete(req.params.id);res.json({success:true});}catch{res.status(500).json({message:'Error'});} });

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
        if (prev.status === 'Converted' && (req.body.status !== undefined || req.body.quotedPrice !== undefined)) {
            return res.status(400).json({ message:'This commission has already been paid for and converted into an order — update the linked order instead.' });
        }
        if (req.body.quotedPrice !== undefined) {
            return res.status(400).json({ message:'Use the Propose Price action to set or change the quoted price.' });
        }
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

app.post('/api/admin/commissions/:id/propose', adminAuth, async (req,res) => {
    try {
        const { price, message } = req.body;
        const p = Number(price);
        if (!p || p <= 0) return res.status(400).json({ message:'Enter a valid price.' });
        const c = await Commission.findById(req.params.id);
        if (!c) return res.status(404).json({ message:'Not found' });
        if (c.status === 'Converted') return res.status(400).json({ message:'This commission has already been paid for and converted into an order.' });
        c.quotedPrice = p;
        c.proposedBy = 'admin';
        c.adminApproved = true;
        c.userApproved = false;
        c.negotiationLog.push({ by:'admin', price:p, message: (message||'').trim() });
        if (c.status === 'New') c.status = 'Quoted';
        await c.save();
        if (c.email) sendMail(c.email, `New Price Proposed — ${c.commissionId} 💬`, commissionNegotiationEmail(c, 'user'));
        res.json({ commission:c });
    } catch(e) { res.status(400).json({ message:e.message }); }
});

app.post('/api/admin/commissions/:id/approve', adminAuth, async (req,res) => {
    try {
        const c = await Commission.findById(req.params.id);
        if (!c) return res.status(404).json({ message:'Not found' });
        if (!c.quotedPrice) return res.status(400).json({ message:'There is no price to approve yet.' });
        if (c.adminApproved) return res.json({ commission:c });
        c.adminApproved = true;
        c.negotiationLog.push({ by:'admin', price:c.quotedPrice, message:'Approved' });
        await c.save();
        if (c.email) sendMail(c.email, `Design Den Approved Your Price — ${c.commissionId} 👍`, commissionNegotiationEmail(c, 'user'));
        res.json({ commission:c });
    } catch(e) { res.status(400).json({ message:e.message }); }
});

app.delete('/api/admin/commissions/:id', adminAuth, async (req,res) => { try{await Commission.findByIdAndDelete(req.params.id);res.json({success:true});}catch{res.status(500).json({message:'Error'});} });

app.get('/api/admin/customers', adminAuth, async (req,res) => {
    try {
        const { search } = req.query;
        const q = search ? { $or:[{ name:new RegExp(search,'i') },{ email:new RegExp(search,'i') }] } : {};
        const users = await User.find(q).select('-password -__v').sort({ createdAt:-1 });
        const counts = await Order.aggregate([{ $group:{ _id:'$userId', count:{ $sum:1 }, total:{ $sum:'$total' } } }]);
        const map = Object.fromEntries(counts.filter(c => c._id).map(c=>[c._id.toString(),c]));
        res.json({ customers: users.map(u => ({ ...u.toObject(), orderCount:map[u._id.toString()]?.count||0, totalSpent:map[u._id.toString()]?.total||0 })) });
    } catch { res.status(500).json({ message:'Failed to fetch customers' }); }
});

app.get('/api/admin/email-log', adminAuth, async (req,res) => {
    try {
        const { status } = req.query;
        const q = status ? { status } : {};
        const logs = await EmailLog.find(q).sort({ createdAt:-1 }).limit(200);
        const failedCount = await EmailLog.countDocuments({ status:'failed' });
        res.json({ logs, failedCount });
    } catch { res.status(500).json({ message:'Failed to fetch email log' }); }
});

app.get('/api/admin/email-transport-status', adminAuth, async (req,res) => {
    res.json({
        configured: mailerStatus.configured,
        ok: mailerStatus.ok,
        error: mailerStatus.error,
        checkedAt: mailerStatus.checkedAt,
        transport: mailerStatus.transport,
        fromAddress: mailerStatus.configured ? EMAIL_FROM_ADDRESS : null
    });
});

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

app.use((req,res) => res.status(404).json({ message:`${req.method} ${req.originalUrl} not found` }));
app.use((err,req,res,_next) => {
    if (err.message === 'Not allowed by CORS') {
        return res.status(403).json({ message:'This origin is not permitted to access the API.' });
    }
    console.error('[Unhandled]',err); res.status(500).json({ message:'Internal server error' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
    console.log('\n🧶 ══════════════════════════════════════════════');
    console.log(`   Design Den API  →  http://localhost:${PORT}`);
    console.log('══════════════════════════════════════════════════\n');
});