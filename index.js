import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import mongoose from "mongoose";
import helmet from "helmet";
import compression from "compression";
import NodeCache from "node-cache";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import os from "os";
import crypto from "crypto";
import bcrypt from "bcrypt"; // npm install bcrypt
import jwt from "jsonwebtoken"; // npm install jsonwebtoken
import sharp from "sharp"; // npm install sharp

dotenv.config();
const app = express();

// ════════════════════════════════════════════════════════════
// 🔥 FIXED CORS
// ════════════════════════════════════════════════════════════

const allowedOrigins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "https://oneshop.pre.bd",
    "https://income-suitable-codes-mil.trycloudflare.com",
    "https://h9zgeyv2sm.localto.net",
    "https://surl.li/bzxoju",
    "https://shazadhossain-ih61-ma5.tail72a7a3.ts.net",
    "https://jx363nwt-5000.inc1.devtunnels.ms"
];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error("Not allowed by CORS"));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'x-api-key', 'api-key', 'Authorization', 'localtonet-skip-warning', 'ngrok-skip-browser-warning'],
    credentials: false,
    optionsSuccessStatus: 200,
    preflightContinue: false,
}));

app.set('trust proxy', 1);

// প্রতিটা response-এ no-cache header — যাতে browser/CDN/dev-tunnel পুরনো (stale) JSON
// কখনো serve না করে, সবসময় fresh data আসে (304 cache bug ঠেকানোর জন্য)
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});

// ════════════════════════════════════════════════════════════
// 📦 Middleware
// ════════════════════════════════════════════════════════════

app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginOpenerPolicy: false,
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false,
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(compression());

// ════════════════════════════════════════════════════════════
// 🚦 Rate Limiter (general)
// ════════════════════════════════════════════════════════════

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 2000,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip || req.headers['x-forwarded-for'] || 'unknown',
    skip: (req) => req.method === 'OPTIONS'
});
app.use(limiter);

// 🔒 STRICT limiter — শুধু auth-sensitive routes-এ (brute-force ঠেকাতে)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip || req.headers['x-forwarded-for'] || 'unknown',
    skip: (req) => req.method === 'OPTIONS',
    message: { success: false, error: 'অনেকবার চেষ্টা করা হয়েছে, কিছুক্ষণ পর আবার চেষ্টা করুন' },
});

app.disable('x-powered-by');

// ════════════════════════════════════════════════════════════
// 🔑 API Key Middleware
// ════════════════════════════════════════════════════════════

const API_KEY = process.env.API_KEY || 'one-shop-secret-key-change-this';

const requireApiKey = (req, res, next) => {
    if (req.method === 'OPTIONS') return next();
    const key = req.headers['x-api-key'];
    if (!key || key !== API_KEY) {
        return res.status(401).json({ success: false, error: 'Unauthorized - x-api-key header দিন' });
    }
    next();
};

// ════════════════════════════════════════════════════════════
// 🖼️ Cloudinary Fetch Proxy (email-safe image URLs)
// ════════════════════════════════════════════════════════════

function toCloudinaryUrl(rawUrl) {
    if (!rawUrl) return rawUrl;
    const CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
    return `https://res.cloudinary.com/${CLOUD_NAME}/image/fetch/f_auto,q_auto/${encodeURIComponent(rawUrl)}`;
}

// ════════════════════════════════════════════════════════════
// ⭐ Review token (email-থেকে one-click rating এর জন্য, spoof-proof)
// ════════════════════════════════════════════════════════════

function makeReviewToken(productId, email) {
    const secret = process.env.API_KEY || 'one-shop-secret-key-change-this';
    return crypto.createHmac('sha256', secret).update(`${productId}:${email}`).digest('hex').slice(0, 16);
}

// ════════════════════════════════════════════════════════════
// 🔐 Password helpers (bcrypt + lazy migration)
// ════════════════════════════════════════════════════════════

const BCRYPT_ROUNDS = 10;

function isBcryptHash(value) {
    return typeof value === 'string' && /^\$2[aby]\$\d{2}\$/.test(value);
}

async function hashPassword(plain) {
    return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

async function verifyAndMaybeMigratePassword(plainInput, doc) {
    if (!doc || !doc.password) return false;

    if (isBcryptHash(doc.password)) {
        return bcrypt.compare(plainInput, doc.password);
    }

    const matches = doc.password === plainInput;
    if (matches) {
        try {
            doc.password = await hashPassword(plainInput);
            await doc.save();
            console.log(`🔐 Password auto-migrated to bcrypt for: ${doc.email}`);
        } catch (err) {
            console.error('⚠️ Password migration save failed:', err.message);
        }
    }
    return matches;
}

// ════════════════════════════════════════════════════════════
// 🪙 JWT helpers
// ════════════════════════════════════════════════════════════

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = '7d';
const USER_JWT_EXPIRES_IN = '30d';

// এখানে আপনার admin-এর email বসান — এই email-এর token-এই শুধু isAdmin: true হবে
const ADMIN_EMAIL = "shazadahamed571@gmail.com";

if (!JWT_SECRET) {
    console.error('❌ JWT_SECRET .env এ সেট করা নেই! সার্ভার বন্ধ করা হচ্ছে।');
    process.exit(1);
}

// ── Seller token ─────────────────────────────────────────────────────
function generateSellerToken(seller) {
    return jwt.sign(
        { id: seller._id, email: seller.email, role: seller.role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
}

function requireSellerToken(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
        return res.status(401).json({ success: false, error: 'Token নেই, আবার login করো' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'seller') {
            return res.status(403).json({ success: false, error: 'Access নেই' });
        }
        req.seller = decoded; // { id, email, role }
        next();
    } catch (err) {
        return res.status(401).json({ success: false, error: 'Token মেয়াদ শেষ বা invalid, আবার login করো' });
    }
}

// ── Normal user token (Google OAuth / email-password login) ──────────
// isAdmin flag token-এর ভেতরেই sign করা থাকে — backend নিজেই email
// দেখে ঠিক করে, frontend থেকে পাঠানো কোনো "isAdmin" ফ্ল্যাগ বিশ্বাস
// করা হয় না (সেটা spoof করা সহজ হতো)।
function generateUserToken(user) {
    return jwt.sign(
        {
            id: user._id,
            email: user.email,
            name: user.name,
            isAdmin: user.email === ADMIN_EMAIL,
        },
        JWT_SECRET,
        { expiresIn: USER_JWT_EXPIRES_IN }
    );
}

function requireUserToken(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
        return res.status(401).json({ success: false, error: 'Token নেই, আবার login করো' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // { id, email, name, isAdmin }
        next();
    } catch (err) {
        return res.status(401).json({ success: false, error: 'Token মেয়াদ শেষ বা invalid, আবার login করো' });
    }
}

// ── Admin-only middleware — requireUserToken-এর পরেই বসাতে হবে ───────
function requireAdmin(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
        return res.status(401).json({ success: false, error: 'Token নেই, login করো' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded.isAdmin) {
            return res.status(403).json({ success: false, error: 'Admin access নেই' });
        }
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, error: 'Token মেয়াদ শেষ বা invalid, আবার login করো' });
    }
}

// ════════════════════════════════════════════════════════════
// 🚚 Steadfast Courier API
// ════════════════════════════════════════════════════════════
// .env এ বসাও:
//   STEADFAST_API_KEY=xxxxx
//   STEADFAST_SECRET_KEY=xxxxx
//   STEADFAST_BASE_URL=https://portal.packzy.com/api/v1   (default, না দিলেও চলবে)
//
// ⚠️ NOTE: এখন থেকে অর্ডার প্লেস হলে আর অটোমেটিক Steadfast-এ বুক হয় না।
// প্রধান courier flow এখন Paperfly (নিচে দেখুন) — dynamic pickup address-এর
// জন্য এটাই দরকার ছিল, কারণ Steadfast-এ per-order pickup address সাপোর্ট নেই।
// Steadfast-এর routes/helpers এখানে রাখা হলো (অপশনাল/ব্যাকআপ হিসেবে ব্যবহার
// করতে চাইলে), কিন্তু bookOrderWithSteadfast() আর কোথাও call হয় না।

// ════════════════════════════════════════════════════════════
// 💰 Platform Commission
// ════════════════════════════════════════════════════════════
// প্রতিটা delivered order-এর মূল্যের ৫% আমাদের প্ল্যাটফর্মের কমিশন হিসেবে
// কাটা হয়, বাকি ৯৫% সেলারের প্রাপ্য (seller payout)। .env-এ
// PLATFORM_COMMISSION_RATE দিয়ে ওভাররাইড করা যায় (যেমন 0.07 = ৭%)।
const PLATFORM_COMMISSION_RATE = Number(process.env.PLATFORM_COMMISSION_RATE) || 0.05;

const STEADFAST_BASE_URL = process.env.STEADFAST_BASE_URL || 'https://portal.packzy.com/api/v1';
const STEADFAST_API_KEY = process.env.STEADFAST_API_KEY;
const STEADFAST_SECRET_KEY = process.env.STEADFAST_SECRET_KEY;

async function steadfastRequest(method, path, body) {
    if (!STEADFAST_API_KEY || !STEADFAST_SECRET_KEY) {
        throw new Error('STEADFAST_API_KEY / STEADFAST_SECRET_KEY .env এ সেট নেই');
    }
    const res = await fetch(`${STEADFAST_BASE_URL}${path}`, {
        method,
        headers: {
            'Content-Type': 'application/json',
            'Api-Key': STEADFAST_API_KEY,
            'Secret-Key': STEADFAST_SECRET_KEY,
        },
        body: body ? JSON.stringify(body) : undefined,
    });

    const text = await res.text();
    let data;
    try {
        data = JSON.parse(text);
    } catch {
        data = { raw: text };
    }

    if (!res.ok) {
        const err = new Error(data?.message || `Steadfast API error (${res.status})`);
        err.status = res.status;
        err.data = data;
        throw err;
    }
    return data;
}

// raw Steadfast status কে frontend-friendly একটা ছোট set এ normalize করে
function normalizeCourierStatus(rawStatus) {
    const s = String(rawStatus || '').toLowerCase();
    if (!s) return 'unknown';
    if (s.includes('deliver') && !s.includes('partial') && !s.includes('cancel')) return 'delivered';
    if (s.includes('partial')) return 'partial_delivered';
    if (s.includes('cancel')) return 'cancelled';
    if (s.includes('return') || s.includes('hold')) return 'returned';
    if (s.includes('transit') || s.includes('hub') || s.includes('out_for')) return 'in_transit';
    if (s.includes('pending') || s.includes('review') || s.includes('approval')) return 'processing';
    return 'processing';
}

// ⚠️ এখন আর কোথাও call হয় না (Paperfly ফ্লো ব্যবহার হচ্ছে), কিন্তু ফাংশনটা রাখা
// হলো — চাইলে ব্যাকআপ courier হিসেবে ভবিষ্যতে re-enable করতে পারবেন।
async function bookOrderWithSteadfast(orderDoc) {
    try {
        if (!STEADFAST_API_KEY || !STEADFAST_SECRET_KEY) return; // courier সেটআপ না থাকলে চুপচাপ skip

        const invoice = String(orderDoc._id);
        const payload = {
            invoice,
            recipient_name: orderDoc.name || 'Customer',
            recipient_phone: getOrderPhone(orderDoc),
            recipient_address: orderDoc.address || '',
            cod_amount: Number(orderDoc.price) * Number(orderDoc.quantity || 1) || 0,
            note: orderDoc.note || '',
            item_description: orderDoc.title || orderDoc.name || 'Product',
        };

        if (!payload.recipient_phone || !payload.recipient_address) {
            console.warn(`⚠️ Steadfast auto-book skip (phone/address missing) — order ${invoice}`);
            return;
        }

        const result = await steadfastRequest('POST', '/create_order', payload);
        const consignment = result?.consignment;
        if (consignment) {
            await orderdata.findByIdAndUpdate(orderDoc._id, {
                $set: {
                    steadfast_consignment_id: consignment.consignment_id,
                    steadfast_tracking_code: consignment.tracking_code,
                    steadfast_invoice: invoice,
                    courier_status: normalizeCourierStatus(consignment.status),
                },
            });
            console.log(`🚚 Steadfast booked — order ${invoice} → consignment ${consignment.consignment_id}`);
        }
    } catch (err) {
        console.error('❌ Steadfast auto-book failed:', err.message);
    }
}

// ════════════════════════════════════════════════════════════
// 📦 Paperfly Courier API
// ════════════════════════════════════════════════════════════
// .env এ বসাও:
//   PAPERFLY_USERNAME=xxxxx     (merchant panel username)
//   PAPERFLY_PASSWORD=xxxxx     (merchant panel password)
//   PAPERFLY_KEY=xxxxx          (Paperfly দেওয়া ফিক্সড key, header এ যায়)
//
// 🎯 এখানেই dynamic pickup address-এর আসল লজিক:
// Paperfly-এর order create API-তে সরাসরি ঠিকানা পাঠানো যায় না, শুধু
// "storeName" পাঠাতে হয় — যেই নামের Store Paperfly merchant panel-এ
// আগে থেকে (ম্যানুয়ালি) তৈরি করা আছে। তাই প্রতিটা seller-এর নিজস্ব
// Store বানিয়ে সেই নামটা আমাদের DB-এর Store collection-এ
// `paperfly_store_name` ফিল্ডে সেভ রাখা হয়, আর অর্ডার বুক করার সময়
// প্রোডাক্টের seller_email দিয়ে সেই store বের করে storeName হিসেবে
// পাঠানো হয় — এটাই "সেলার অনুযায়ী ডাইনামিক পিকআপ"।

const PAPERFLY_BASE_URL = 'https://api.paperfly.com.bd';
const PAPERFLY_USERNAME = process.env.PAPERFLY_USERNAME;
const PAPERFLY_PASSWORD = process.env.PAPERFLY_PASSWORD;
const PAPERFLY_KEY = process.env.PAPERFLY_KEY;

async function paperflyRequest(path, body) {
    if (!PAPERFLY_USERNAME || !PAPERFLY_PASSWORD || !PAPERFLY_KEY) {
        throw new Error('PAPERFLY_USERNAME / PAPERFLY_PASSWORD / PAPERFLY_KEY .env এ সেট নেই');
    }
    const basicAuth = Buffer.from(`${PAPERFLY_USERNAME}:${PAPERFLY_PASSWORD}`).toString('base64');

    const res = await fetch(`${PAPERFLY_BASE_URL}${path}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Basic ${basicAuth}`,
            'paperflykey': PAPERFLY_KEY,
        },
        body: JSON.stringify(body),
    });

    const text = await res.text();
    let data;
    try {
        data = JSON.parse(text);
    } catch {
        data = { raw: text };
    }

    if (!res.ok) {
        const err = new Error(data?.error?.message || data?.message || `Paperfly API error (${res.status})`);
        err.status = res.status;
        err.data = data;
        throw err;
    }
    return data;
}

// Paperfly-এর trackingStatus object কে normalized status-এ রূপান্তর করে।
// এটাই "processing → delivered" edit হওয়ার আসল জায়গা: Paperfly যেই stage-এ
// আছে তার উপর ভিত্তি করে DB-এর courier_status ফিল্ড এই মানগুলার একটায়
// বদলে যায় — sync function-এ এই status-ই DB-তে $set হয়।
function normalizePaperflyStatus(trackingStatus) {
    if (!trackingStatus) return 'processing';
    const has = (v) => v !== undefined && v !== null && String(v).trim() !== '';

    if (has(trackingStatus.Delivered)) return 'delivered';
    if (has(trackingStatus.Partial)) return 'partial_delivered';
    if (has(trackingStatus.Returned)) return 'returned';
    if (has(trackingStatus.close) && !has(trackingStatus.Delivered)) return 'cancelled';
    if (has(trackingStatus.PickedForDelivery)) return 'in_transit';
    if (has(trackingStatus.ReceivedAtPoint)) return 'in_transit';
    if (has(trackingStatus.inTransit)) return 'in_transit';
    if (has(trackingStatus.Pick)) return 'processing';
    if (has(trackingStatus.onHoldSchedule)) return 'processing';
    return 'processing';
}

// অর্ডার document-এ ফোন নম্বর কোন নামে সেভ আছে তা নিশ্চিত না — চেকআউট ফর্ম
// versions ভেদে "phone", "contact_number", বা "phonenumber" — এই তিনটাই
// চেক করে যেটা পাওয়া যায় সেটা রিটার্ন করে। নতুন কোনো নাম যোগ হলে শুধু এই
// একটা জায়গায় যোগ করলেই সব রুটে কাজ করবে।
function getOrderPhone(order) {
    return order?.phone || order?.contact_number || order?.phonenumber || '';
}

// যেকোনো ফরম্যাটের বাংলাদেশি নম্বরকে Paperfly-এর প্রত্যাশিত standard
// "01XXXXXXXXX" (১১ ডিজিট, শূন্য দিয়ে শুরু) ফরম্যাটে normalize করে।
// হ্যান্ডেল করে: স্পেস/ড্যাশ/বন্ধনী, +880 / 880 প্রিফিক্স, leading zero মিসিং।
// normalize করতে না পারলে null রিটার্ন করে — তখন booking-এর আগেই আটকানো হয়,
// Paperfly থেকে "Invalid Receiver phone number" error না খেয়ে।
function normalizeBdPhone(raw) {
    if (!raw) return null;
    let digits = String(raw).replace(/[^\d]/g, ''); // স্পেস/ড্যাশ/+/বন্ধনী সব বাদ

    if (digits.startsWith('880')) {
        digits = digits.slice(3); // 8801712345678 → 1712345678
    }
    if (!digits.startsWith('0')) {
        digits = '0' + digits; // 1712345678 → 01712345678
    }

    // বাংলাদেশি মোবাইল: ঠিক ১১ ডিজিট, 01 দিয়ে শুরু, তৃতীয় ডিজিট 3-9
    if (/^01[3-9]\d{8}$/.test(digits)) {
        return digits;
    }
    return null;
}

// order doc + সেলারের store name থেকে Paperfly order payload বানায়
function buildPaperflyPayload(orderDoc, storeName, merchantOrderReference) {
    const normalizedPhone = normalizeBdPhone(getOrderPhone(orderDoc));
    return {
        merchantOrderReference,
        storeName, // ← dynamic pickup — সেলার অনুযায়ী বদলায়
        productBrief: orderDoc.title || orderDoc.name || 'Product',
        packagePrice: String(Number(orderDoc.price) * Number(orderDoc.quantity || 1) || 0),
        max_weight: String(orderDoc.weight || '0.5'),
        customerName: orderDoc.name || 'Customer',
        customerAddress: orderDoc.address || '',
        customerPhone: normalizedPhone || '', // normalize না হলে খালি — validation ধরে ফেলবে
    };
}

// একটা single order-এর status Paperfly থেকে টেনে DB-তে write-back করে।
// রিটার্ন করে normalized status (বদলায়নি হলেও)।
async function syncOnePaperflyOrderStatus(orderDoc) {
    if (!orderDoc.paperfly_order_ref) {
        return orderDoc.courier_status || 'pending_confirmation';
    }

    const result = await paperflyRequest('/API-Order-Tracking', {
        ReferenceNumber: orderDoc.paperfly_order_ref,
    });

    const trackingStatus = result?.success?.trackingStatus?.[0] || null;
    const normalized = normalizePaperflyStatus(trackingStatus);

    if (orderDoc.courier_status !== normalized) {
        await orderdata.findByIdAndUpdate(orderDoc._id, {
            $set: { courier_status: normalized, paperfly_last_synced_at: new Date() },
        });
    }
    return normalized;
}

// অনেকগুলো order একসাথে sync করার জন্য (periodic background job + manual admin trigger দুটোতেই ব্যবহার হয়)
async function syncManyPaperflyOrders(orders) {
    const results = [];
    for (const order of orders) {
        try {
            const status = await syncOnePaperflyOrderStatus(order);
            results.push({ orderId: order._id, success: true, status });
        } catch (err) {
            results.push({ orderId: order._id, success: false, error: err.message });
        }
    }
    return results;
}

// ════════════════════════════════════════════════════════════
// 🗄️ MongoDB Connection
// ════════════════════════════════════════════════════════════

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/oneshop';

try {
    await mongoose.connect(MONGO_URI, {
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        maxPoolSize: 10,
    });
    console.log('✅ MongoDB connected');
} catch (err) {
    console.error('❌ DB Error:', err);
    process.exit(1);
}

mongoose.set('sanitizeFilter', true);

// ════════════════════════════════════════════════════════════
// 📊 Models
// ════════════════════════════════════════════════════════════

const shopSchema = new mongoose.Schema({
    productId: { type: Number, required: true },
    email: { type: String, required: true },
    comment: { type: String, required: true },
    imageUrl: { type: String, default: null },
    rating: { type: Number, min: 1, max: 5, default: null },
}, { strict: false, timestamps: true });

const ShopModel = mongoose.model('Shop', shopSchema, 'one-shop-coll');
const FloatingDataModel = mongoose.model('FloatingData', new mongoose.Schema({}, { strict: false }), 'flotingdata');

const userLoginSchema = new mongoose.Schema({}, { strict: false });
userLoginSchema.index({ email: 1 }, { unique: true, sparse: true });
const userlogindata = mongoose.model('user-login-data', userLoginSchema, 'user-login-data');

const cartitem = mongoose.model('cart-item', new mongoose.Schema({}, { strict: false }), 'cartdata');
const locationdata = mongoose.model('location-data', new mongoose.Schema({}, { strict: false }), 'userlocationdata');
const orderdata = mongoose.model('order-data', new mongoose.Schema({}, { strict: false }), 'orderdata');
const total_products = mongoose.model(
    'total-products',
    new mongoose.Schema({}, { strict: false, id: false }),
    'total_product'
);
const sellerSchema = new mongoose.Schema({}, { strict: false });
sellerSchema.index({ email: 1 }, { unique: true, sparse: true });
const Selleregister = mongoose.model('selleregister', sellerSchema, 'selleregister');

// ── Store: প্রতিটা seller-এর একটাই store, email দিয়ে unique ───────────
// strict:false থাকায় paperfly_store_name ফিল্ড কোনো schema change ছাড়াই যোগ হয়ে যায়
const storeSchema = new mongoose.Schema({}, { strict: false });
storeSchema.index({ email: 1 }, { unique: true, sparse: true });
const Store = mongoose.model('store', storeSchema, 'storedata');

// ── Counter: product-এর জন্য unique, sequential id generate করতে ─────
const counterSchema = new mongoose.Schema({ _id: String, seq: { type: Number, default: 0 } });
const Counter = mongoose.model('counter', counterSchema, 'counters');

// ════════════════════════════════════════════════════════════
// 🔢 Product ID Counter (atomic — race condition ফ্রি)
// ════════════════════════════════════════════════════════════

let idCache = {
    nextId: null,
    lastRefreshed: 0,
};
const ID_CACHE_TTL_MS = 60 * 60 * 1000;

async function getNextProductId() {
    const now = Date.now();
    if (idCache.nextId === null || (now - idCache.lastRefreshed) > ID_CACHE_TTL_MS) {
        const count = await total_products.countDocuments({});
        idCache.nextId = 10001 + count;
        idCache.lastRefreshed = now;
    }
    const id = idCache.nextId;
    idCache.nextId += 1;
    return id;
}

// সার্ভার শুরুতে একবারই counter কে existing product-দের max id থেকে seed করে —
// counter doc আগে থেকে থাকলে কিছুই করে না। দুটো instance একসাথে seed করতে
// গেলেও (duplicate key error) নিরাপদে ignore করা হয়।
async function ensureProductCounterSeeded() {
    const existingCounter = await Counter.findById('total_products');
    if (existingCounter) return;
    const maxDoc = await total_products.findOne().sort({ id: -1 }).select('id').lean();
    const startFrom = (maxDoc && Number(maxDoc.id)) || 0;
    try {
        await Counter.create({ _id: 'total_products', seq: startFrom });
        console.log(`🔢 Product counter seeded from ${startFrom}`);
    } catch (err) {
        if (err.code !== 11000) throw err; // অন্য কেউ ইতিমধ্যে seed করে ফেলেছে, ঠিক আছে
    }
}
await ensureProductCounterSeeded();

// ════════════════════════════════════════════════════════════
// 🗂️ Cache
// ════════════════════════════════════════════════════════════

const cache = new NodeCache({ stdTTL: 60, checkperiod: 120 });
const getCache = (k) => cache.get(k);
const setCache = (k, v, ttl) => cache.set(k, v, ttl ?? 60);
const delCache = (k) => cache.del(k);

// ════════════════════════════════════════════════════════════
// 📧 Email Transporter
// ════════════════════════════════════════════════════════════

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
});

const otpStore = new Map();

// ════════════════════════════════════════════════════════════
// 🛠️ Helper Functions
// ════════════════════════════════════════════════════════════

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email));
const CARD_SELECT = 'id title name   sale_price image thumbnail_img category stock_status';

function makeFilter(id) {
    const n = parseInt(id, 10);
    if (isNaN(n)) return null;
    return { id: n };
}

// ── ছবি compress করে ~targetKB এ নামিয়ে আনে (iterative quality/size cut) ─
async function compressImageToTargetKB(base64Input, targetKB = 30) {
    if (!base64Input || typeof base64Input !== 'string') return null;

    const match = base64Input.match(/^data:(image\/\w+);base64,(.+)$/);
    const raw = match ? match[2] : base64Input;
    const inputBuffer = Buffer.from(raw, 'base64');

    let quality = 78;
    let width = 900;
    let output = null;

    for (let attempt = 0; attempt < 10; attempt++) {
        try {
            output = await sharp(inputBuffer)
                .rotate() // EXIF orientation অনুযায়ী সোজা করে
                .resize({ width, withoutEnlargement: true })
                .jpeg({ quality, mozjpeg: true })
                .toBuffer();
        } catch (err) {
            console.error('⚠️ Image compress failed:', err.message);
            return null;
        }

        if (output.length <= targetKB * 1024) break;

        if (quality > 30) {
            quality -= 12;
        } else {
            quality = 40;
            width = Math.round(width * 0.75);
        }
        if (width < 100) break; // নিরাপত্তা limit, খুব ছোট হয়ে যাওয়া আটকাতে
    }

    return `data:image/jpeg;base64,${output.toString('base64')}`;
}

// ════════════════════════════════════════════════════════════
// 📧 Order & Cart Email Helpers
// ════════════════════════════════════════════════════════════

function buildReviewSection(id, email) {
    if (!id || !email) return '';
    const token = makeReviewToken(id, email);
    const base = `https://debian.tail72a7a3.ts.net/reviews/quick-rate?productId=${id}&email=${encodeURIComponent(email)}&token=${token}`;
    let stars = '';
    for (let i = 1; i <= 5; i++) {
        stars += `<a href="${base}&rating=${i}" style="text-decoration:none;font-size:26px;color:#fbbf24;margin:0 3px;">⭐</a>`;
    }
    return `
    <div style="text-align:center;margin-top:20px;padding-top:16px;border-top:1px solid #334155;">
      <p style="color:#94a3b8;font-size:14px;margin-bottom:8px;">প্রোডাক্টটি কেমন লাগলো? রেট করো:</p>
      <div style="margin-bottom:14px;">${stars}</div>
      <a href="https://oneshop.pre.bd/product/${id}" style="display:inline-block;background:#22c55e;color:#0f172a;font-weight:bold;text-decoration:none;padding:10px 20px;border-radius:8px;font-size:14px;">বিস্তারিত রিভিউ লিখুন</a>
    </div>`;
}

function buildProductEmailHtml({ heading, subheading, id, title, image, price, quantity, size, category, address, email, showReview }) {
    return `
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;background:#0f172a;color:#f1f5f9;border-radius:12px;">
      <h2 style="color:#22c55e;margin-bottom:4px;">${heading}</h2>
      <p style="color:#94a3b8;margin-top:0;">${subheading}</p>
      <a href="https://oneshop.pre.bd/product/${id}" style="text-decoration:none;color:inherit;">
        <div style="display:flex;gap:12px;align-items:center;background:#1e293b;padding:12px;border-radius:8px;margin:16px 0;">
          <img src="${image || ''}" width="64" height="64" style="border-radius:8px;object-fit:contain;background:#fff;padding:4px;" alt="${title || 'Product'}" />
          <div>
            <p style="margin:0;font-weight:bold;">${title || 'Product'}</p>
            <p style="margin:4px 0 0;font-size:13px;color:#94a3b8;">${category || ''} ${size ? `• Size: ${size}` : ''} • Qty: ${quantity || 1}</p>
          </div>
        </div>
      </a>
      <p style="font-size:13px;color:#94a3b8;">Product ID: ${id}</p>
      <p style="font-size:18px;font-weight:bold;color:#22c55e;">৳${price ?? 0}</p>
      ${address ? `<p style="font-size:13px;color:#94a3b8;">Delivery Address: ${address}</p>` : ''}
      <p style="margin-top:20px;font-size:13px;color:#64748b;">ধন্যবাদ ONE-SHOP-এ কেনাকাটা করার জন্য।</p>
      ${showReview ? buildReviewSection(id, email) : ''}
    </div>`;
}

function buildProductEmailText({ heading, subheading, id, title, price, quantity, size, category, address, showReview }) {
    return `${heading}
${subheading}

${title || 'Product'}
${id ? `Product ID: ${id}` : ''}
${category || ''} ${size ? `Size: ${size}` : ''} Qty: ${quantity || 1}
৳${price ?? 0}
${address ? `Delivery Address: ${address}` : ''}

ধন্যবাদ ONE-SHOP-এ কেনাকাটা করার জন্য।
${showReview && id ? `\nরিভিউ দিতে: https://oneshop.pre.bd/product/${id}` : ''}`;
}

async function sendProductEmail(to, html, subject, text) {
    if (!to || !isValidEmail(to)) return;
    try {
        await transporter.sendMail({
            from: `"ONE-SHOP" <${process.env.EMAIL_USER}>`,
            to,
            replyTo: process.env.EMAIL_USER,
            subject,
            text: text || subject,
            html,
        });
        console.log(`📧 Email sent to ${to}: ${subject}`);
    } catch (err) {
        console.error('❌ Email send failed:', err.message);
    }
}

// ════════════════════════════════════════════════════════════
// 🌐 Routes
// ════════════════════════════════════════════════════════════

app.get('/', (req, res) => {
    res.json({ status: 'OK', message: 'Server is running' });
});

// ── SELLER: TOKEN VERIFY ────────────────────────────────────────────
app.get('/seller/verify-token', requireSellerToken, async (req, res) => {
    try {
        const seller = await Selleregister.findById(req.seller.id).select('-password');
        if (!seller) {
            return res.status(404).json({ success: false, error: 'Seller account পাওয়া যায়নি' });
        }
        res.json({
            success: true,
            seller: { id: seller._id, name: seller.name, email: seller.email, phone: seller.phone, address: seller.address },
        });
    } catch (err) {
        console.error('❌ seller/verify-token:', err);
        res.status(500).json({ success: false, error: 'Verify করা যায়নি' });
    }
});

// ── SELLER FORGOT PASSWORD — email OTP দিয়ে ────────────────────────
app.post('/seller/forgot-password', authLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, error: 'Valid email দাও' });
        }

        const seller = await Selleregister.findOne({ email });
        if (!seller) {
            return res.json({ success: false, error: 'এই email এ কোনো seller account নেই' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore.set(`seller_reset_${email}`, { otp, expiresAt: Date.now() + 10 * 60 * 1000 });

        await transporter.sendMail({
            from: `"ONE-SHOP" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Seller Password Reset OTP',
            html: `<div style="font-family:Arial;max-width:480px;margin:auto;padding:32px;background:#0f172a;color:#f1f5f9;"><h2 style="color:#3b82f6;">🔐 Seller Password Reset</h2><p>OTP: <span style="font-size:32px;font-weight:bold;color:#3b82f6;">${otp}</span></p><p>১০ মিনিট valid</p></div>`,
        });

        res.json({ success: true, message: 'OTP পাঠানো হয়েছে' });
    } catch (err) {
        console.error('❌ seller/forgot-password:', err);
        res.status(500).json({ success: false, error: 'OTP পাঠানো যায়নি' });
    }
});

// ── SELLER VERIFY OTP ────────────────────────────────────────────────
app.post('/seller/verify-otp', authLimiter, (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) {
        return res.status(400).json({ success: false, error: 'Email ও OTP দাও' });
    }
    const record = otpStore.get(`seller_reset_${email}`);
    if (!record) {
        return res.json({ success: false, error: 'OTP পাওয়া যায়নি' });
    }
    if (Date.now() > record.expiresAt) {
        otpStore.delete(`seller_reset_${email}`);
        return res.json({ success: false, error: 'OTP মেয়াদ শেষ' });
    }
    if (record.otp !== otp) {
        return res.json({ success: false, error: 'OTP ভুল' });
    }
    res.json({ success: true, message: 'OTP সঠিক' });
});

// ── SELLER RESET PASSWORD ────────────────────────────────────────────
app.post('/seller/reset-password', authLimiter, async (req, res) => {
    try {
        const { email, newPassword } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, error: 'Valid email দাও' });
        }
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ success: false, error: 'Password কমপক্ষে ৬ character' });
        }

        const record = otpStore.get(`seller_reset_${email}`);
        if (!record || Date.now() > record.expiresAt) {
            return res.json({ success: false, error: 'আগে OTP verify করো' });
        }

        const hashed = await hashPassword(newPassword);
        const updated = await Selleregister.findOneAndUpdate(
            { email },
            { $set: { password: hashed } },
            { new: true }
        );
        if (!updated) {
            return res.json({ success: false, error: 'Seller পাওয়া যায়নি' });
        }

        otpStore.delete(`seller_reset_${email}`);
        res.json({ success: true, message: 'Password পরিবর্তন হয়েছে' });
    } catch (err) {
        console.error('❌ seller/reset-password:', err);
        res.status(500).json({ success: false, error: 'Password reset হয়নি' });
    }
});

// ── SELLER LOGIN ──────────────────────────────────────────────────────
app.post('/seller_login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, error: 'Email ও Password দাও' });
        }

        const seller = await Selleregister.findOne({ email });
        if (!seller) {
            return res.json({ success: false, error: 'এই email এ কোনো seller account নেই, আগে register করো' });
        }

        const ok = await verifyAndMaybeMigratePassword(password, seller);
        if (!ok) {
            return res.json({ success: false, error: 'ভুল password' });
        }

        const token = generateSellerToken(seller);

        res.json({
            success: true,
            message: 'Login successful',
            token,
            seller: {
                id: seller._id,
                name: seller.name,
                email: seller.email,
                phone: seller.phone,
                address: seller.address,
            },
        });
    } catch (err) {
        console.error('❌ Seller login failed:', err);
        res.status(500).json({ success: false, error: 'Login করা যায়নি' });
    }
});

// ── STEP 1: registration OTP ──────────────────────────────────────────
app.post('/seller/send-otp', authLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, error: 'Valid email দাও' });
        }

        const existingSeller = await Selleregister.findOne({ email });
        if (existingSeller) {
            return res.json({ success: false, error: 'এই email দিয়ে আগেই একটা seller account আছে' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore.set(`seller_${email}`, { otp, expiresAt: Date.now() + 10 * 60 * 1000 });

        await transporter.sendMail({
            from: `"ONE-SHOP" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Seller Registration OTP',
            html: `<div style="font-family:Arial;max-width:480px;margin:auto;padding:32px;background:#0f172a;color:#f1f5f9;"><h2 style="color:#3b82f6;">🏪 Seller Registration OTP</h2><p>OTP: <span style="font-size:32px;font-weight:bold;color:#3b82f6;">${otp}</span></p><p>১০ মিনিট valid</p></div>`,
        });

        res.json({ success: true, message: 'OTP পাঠানো হয়েছে' });
    } catch (err) {
        console.error('❌ seller/send-otp:', err);
        res.status(500).json({ success: false, error: 'OTP পাঠানো যায়নি' });
    }
});

// ── STEP 2: OTP check করেই তবে account তৈরি হয় ──────────────────────
app.post('/seller_register', authLimiter, async (req, res) => {
    try {
        const { name, email, phone, role, address, password, otp } = req.body;

        if (!otp) {
            return res.status(400).json({ success: false, error: 'OTP দাও' });
        }
        if (!password || password.length < 6) {
            return res.status(400).json({ success: false, error: 'Password কমপক্ষে ৬ character' });
        }

        const record = otpStore.get(`seller_${email}`);
        if (!record) {
            return res.json({ success: false, error: 'আগে OTP পাঠাও' });
        }
        if (Date.now() > record.expiresAt) {
            otpStore.delete(`seller_${email}`);
            return res.json({ success: false, error: 'OTP মেয়াদ শেষ, আবার পাঠাও' });
        }
        if (record.otp !== otp) {
            return res.json({ success: false, error: 'OTP ভুল' });
        }

        const existingSeller = await Selleregister.findOne({ email });
        if (existingSeller) {
            return res.status(400).json({ success: false, error: 'Seller already registered' });
        }

        const hashed = await hashPassword(password);
        const newSeller = new Selleregister({ name, role: role || 'seller', email, phone, address, password: hashed });
        await newSeller.save();

        otpStore.delete(`seller_${email}`);

        const token = generateSellerToken(newSeller);

        res.json({
            success: true,
            token,
            seller: {
                id: newSeller._id,
                name: newSeller.name,
                email: newSeller.email,
                phone: newSeller.phone,
                address: newSeller.address,
            },
            message: 'Seller registered successfully',
        });
    } catch (err) {
        if (err.code === 11000) {
            return res.status(400).json({ success: false, error: 'Seller already registered' });
        }
        console.error('❌ Seller registration failed:', err);
        res.status(500).json({ success: false, error: 'Failed to register seller' });
    }
});

// ── SELLER: STORE — আছে কিনা check (প্যানেলে ঢোকার সাথে সাথেই কল হয়) ──
app.get('/seller/store', requireSellerToken, async (req, res) => {
    try {
        const store = await Store.findOne({ email: req.seller.email });
        res.json({ success: true, exists: !!store, store: store || null });
    } catch (err) {
        console.error('❌ seller/store GET:', err);
        res.status(500).json({ success: false, error: 'স্টোর তথ্য পাওয়া যায়নি' });
    }
});

// ── SELLER: STORE তৈরি (প্রথমবার — email সবসময় token থেকে, spoof করা যায় না) ──
app.post('/seller/store', requireSellerToken, async (req, res) => {
    try {
        const email = req.seller.email;
        const { store_name, phone, address, profile_image } = req.body;

        if (!store_name || !store_name.trim()) {
            return res.status(400).json({ success: false, error: 'স্টোরের নাম দাও' });
        }
        if (!phone || !String(phone).trim()) {
            return res.status(400).json({ success: false, error: 'ফোন নম্বর দাও' });
        }
        if (!address || !String(address).trim()) {
            return res.status(400).json({ success: false, error: 'পিকআপ ঠিকানা দাও' });
        }
        if (!profile_image) {
            return res.status(400).json({ success: false, error: 'প্রোফাইল ছবি দাও' });
        }

        const already = await Store.findOne({ email });
        if (already) {
            return res.status(400).json({ success: false, error: 'এই email দিয়ে আগেই store তৈরি হয়েছে', store: already });
        }

        const compressedImage = await compressImageToTargetKB(profile_image, 30);
        if (!compressedImage) {
            return res.status(400).json({ success: false, error: 'প্রোফাইল ছবি প্রসেস করা যায়নি' });
        }

        const store = await Store.create({
            seller_id: req.seller.id,
            email,
            store_name: store_name.trim(),
            phone: String(phone).trim(),
            address: String(address).trim(), // ⚠️ req.seller.address না — req.body.address, কারণ JWT token-এ address নেই
            profile_image: compressedImage,
        });

        res.status(201).json({ success: true, store, message: 'স্টোর তৈরি হয়েছে' });
    } catch (err) {
        if (err.code === 11000) {
            return res.status(400).json({ success: false, error: 'এই email দিয়ে আগেই store তৈরি হয়েছে' });
        }
        console.error('❌ seller/store POST:', err);
        res.status(500).json({ success: false, error: 'স্টোর তৈরি করা যায়নি' });
    }
});

// ── SELLER: STORE এডিট (নাম / ফোন / ঠিকানা / প্রোফাইল ছবি বদলানো) ────
app.put('/seller/store', requireSellerToken, async (req, res) => {
    try {
        const email = req.seller.email;
        const { store_name, phone, address, profile_image } = req.body;

        const update = {};
        if (store_name && store_name.trim()) update.store_name = store_name.trim();
        if (phone && String(phone).trim()) update.phone = String(phone).trim();
        if (address && String(address).trim()) update.address = String(address).trim();
        if (profile_image) {
            const compressed = await compressImageToTargetKB(profile_image, 30);
            if (compressed) update.profile_image = compressed;
        }

        if (Object.keys(update).length === 0) {
            return res.status(400).json({ success: false, error: 'কিছুই পরিবর্তন করা হয়নি' });
        }

        const store = await Store.findOneAndUpdate({ email }, { $set: update }, { new: true });
        if (!store) {
            return res.status(404).json({ success: false, error: 'স্টোর পাওয়া যায়নি' });
        }
        res.json({ success: true, store, message: 'স্টোর আপডেট হয়েছে' });
    } catch (err) {
        console.error('❌ seller/store PUT:', err);
        res.status(500).json({ success: false, error: 'স্টোর আপডেট করা যায়নি' });
    }
});

// ── SELLER: PRODUCT যোগ করা — store থাকতেই হবে, id unique auto-generate,
//    ছবি সব ~30KB এ compress করে তারপর DB তে save হয় ────────────────────
app.post('/seller/add-product', requireSellerToken, async (req, res) => {
    try {
        const email = req.seller.email;

        const store = await Store.findOne({ email });
        if (!store) {
            return res.status(400).json({ success: false, error: 'প্রোডাক্ট যোগ করার আগে স্টোর তৈরি করো' });
        }

        const { name, category, price, sale_price, details, images } = req.body;

        if (!name || !name.trim()) {
            return res.status(400).json({ success: false, error: 'প্রোডাক্টের নাম দাও' });
        }
        if (!category || !category.trim()) {
            return res.status(400).json({ success: false, error: 'ক্যাটাগরি দাও' });
        }
        const numericPrice = Number(price);
        if (!Number.isFinite(numericPrice) || numericPrice <= 0) {
            return res.status(400).json({ success: false, error: 'সঠিক মূল্য দাও' });
        }
        const numericSalePrice = Number(sale_price);
        if (!Number.isFinite(numericSalePrice) || numericSalePrice <= 0) {
            return res.status(400).json({ success: false, error: 'সঠিক sale price দাও' });
        }
        if (!details || !details.trim()) {
            return res.status(400).json({ success: false, error: 'বিস্তারিত লিখো' });
        }

        const cleanImages = Array.isArray(images) ? images.filter(Boolean).slice(0, 6) : [];
        if (cleanImages.length === 0) {
            return res.status(400).json({ success: false, error: 'কমপক্ষে একটা প্রোডাক্ট ছবি দাও' });
        }

        const compressedImages = [];
        for (const img of cleanImages) {
            const compressed = await compressImageToTargetKB(img, 30);
            if (compressed) compressedImages.push(compressed);
        }
        if (compressedImages.length === 0) {
            return res.status(400).json({ success: false, error: 'ছবি প্রসেস করা যায়নি, আবার চেষ্টা করো' });
        }
        const id = await getNextProductId();

        const product = await total_products.create({

            seller_id: req.seller.id,
            seller_email: email,
            id: id,
            store_name: store.store_name,
            store_profile_image: store.profile_image,
            phone: store.phone,
            name: name.trim(),
            title: name.trim(),
            category: category.trim(),
            price: numericPrice,
            sale_price: numericSalePrice,
            details: details.trim(),
            stock_status: 'available',
            image: compressedImages[0],
            thumbnail_img: compressedImages[0],
            images: compressedImages,
        });

        res.status(201).json({ success: true, product, message: 'প্রোডাক্ট যুক্ত হয়েছে' });
    } catch (err) {
        console.error('❌ seller/add-product:', err);
        res.status(500).json({ success: false, error: 'প্রোডাক্ট যোগ করা যায়নি' });
    }
});

// ── SELLER: নিজের সব প্রোডাক্ট (email দিয়ে ফিল্টার, pagination সহ) ─────
app.get('/seller/my-products', requireSellerToken, async (req, res) => {
    try {
        const email = req.seller.email;
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(50, parseInt(req.query.limit) || 12);
        const skip = (page - 1) * limit;

        const filter = { seller_email: email };
        const [products, total] = await Promise.all([
            total_products.find(filter).sort({ _id: -1 }).skip(skip).limit(limit).lean(),
            total_products.countDocuments(filter),
        ]);

        res.json({ success: true, products, total, page, hasMore: skip + products.length < total });
    } catch (err) {
        console.error('❌ seller/my-products:', err);
        res.status(500).json({ success: false, error: 'প্রোডাক্ট লিস্ট পাওয়া যায়নি' });
    }
});

// ─── Auth Routes ───

// ── NORMAL USER: TOKEN VERIFY (frontend page-load এ ব্যবহার করবে) ─────
app.get('/verify-user-token', requireUserToken, async (req, res) => {
    try {
        const user = await userlogindata.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ success: false, error: 'User পাওয়া যায়নি' });
        }
        res.json({
            success: true,
            user: { id: user._id, name: user.name, email: user.email, picture: user.picture, isAdmin: req.user.isAdmin },
        });
    } catch (err) {
        console.error('❌ verify-user-token:', err);
        res.status(500).json({ success: false, error: 'Verify করা যায়নি' });
    }
});

app.post('/forgot-password', requireApiKey, authLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, error: 'Valid email দাও' });
        }
        const user = await userlogindata.findOne({ email });
        if (!user) {
            return res.json({ success: false, error: 'এই email এ কোনো account নেই' });
        }
        if (!user.password) {
            return res.json({ success: false, error: 'Google account, password reset হবে না' });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = Date.now() + 10 * 60 * 1000;
        otpStore.set(email, { otp, expiresAt });
        await transporter.sendMail({
            from: `"ONE-SHOP" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset OTP',
            html: `<div style="font-family:Arial;max-width:480px;margin:auto;padding:32px;background:#0f172a;color:#f1f5f9;"><h2 style="color:#3b82f6;">🔐 Password Reset</h2><p>OTP: <span style="font-size:32px;font-weight:bold;color:#3b82f6;">${otp}</span></p><p>১০ মিনিট valid</p></div>`
        });
        res.json({ success: true, message: 'OTP পাঠানো হয়েছে' });
    } catch (err) {
        console.error('❌ forgot-password:', err);
        res.status(500).json({ success: false, error: 'OTP পাঠানো যায়নি' });
    }
});

app.post('/verify-otp', requireApiKey, authLimiter, (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) {
        return res.status(400).json({ success: false, error: 'Email ও OTP দাও' });
    }
    const record = otpStore.get(email);
    if (!record) {
        return res.json({ success: false, error: 'OTP পাওয়া যায়নি' });
    }
    if (Date.now() > record.expiresAt) {
        otpStore.delete(email);
        return res.json({ success: false, error: 'OTP মেয়াদ শেষ' });
    }
    if (record.otp !== otp) {
        return res.json({ success: false, error: 'OTP ভুল' });
    }
    otpStore.delete(email);
    res.json({ success: true, message: 'OTP সঠিক' });
});

app.post('/reset-password', requireApiKey, authLimiter, async (req, res) => {
    try {
        const { email, newPassword } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, error: 'Valid email দাও' });
        }
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ success: false, error: 'Password ৬ character' });
        }
        const hashed = await hashPassword(newPassword);
        const updated = await userlogindata.findOneAndUpdate(
            { email },
            { $set: { password: hashed } },
            { new: true }
        );
        if (!updated) {
            return res.json({ success: false, error: 'User পাওয়া যায়নি' });
        }
        delCache(`user_${email}`);
        res.json({ success: true, message: 'Password পরিবর্তন হয়েছে' });
    } catch (err) {
        console.error('❌ reset-password:', err);
        res.status(500).json({ success: false, error: 'Password reset হয়নি' });
    }
});

// ─── Shop Routes ───

app.get('/shopdata', requireApiKey, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        const category = req.query.category || "";
        const sort = req.query.sort || "";
        const filter = {};
        if (category && category !== "all") filter.category = category;
        let sortObj = {};
        if (sort === "price-low") sortObj = { price: 1 };
        else if (sort === "price-high") sortObj = { price: -1 };
        else if (sort === "rating") sortObj = { "rating.rate": -1 };
        const [products, total] = await Promise.all([
            total_products.find(filter).sort(sortObj).skip(skip).limit(limit),
            total_products.countDocuments(filter),
        ]);
        res.json({ products, total, page, last_page: Math.ceil(total / limit), hasMore: skip + limit < total });
    } catch (err) {
        console.error('Shopdata error:', err);
        res.status(500).json({ error: 'Data pawa jayni' });
    }
});

app.get('/shopdata/search', requireApiKey, async (req, res) => {
    try {
        const q = (req.query.q || "").toString().trim();
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(50, parseInt(req.query.limit) || 20);
        const skip = (page - 1) * limit;
        const category = (req.query.category || "").toString().trim();
        const sort = (req.query.sort || "").toString().trim();

        if (!q) {
            return res.json({ products: [], total: 0, page: 1, last_page: 0, hasMore: false });
        }

        const ck = `search_${q}_p${page}_l${limit}_c${category}_s${sort}`;
        const hit = cache.get(ck);
        if (hit) {
            return res.json(hit);
        }

        const dynamicMaxEdits = q.length > 6 ? 2 : 1;

        const pipeline = [{
            $search: {
                index: "one-shop-search-1",
                compound: {
                    should: [
                        {
                            text: {
                                query: q,
                                path: ["title", "name"],
                                score: { boost: { value: 5 } },
                                fuzzy: { maxEdits: dynamicMaxEdits }
                            }
                        },
                        {
                            text: {
                                query: q,
                                path: ["brand", "category"],
                                score: { boost: { value: 2 } },
                                fuzzy: { maxEdits: dynamicMaxEdits }
                            }
                        },
                        {
                            text: {
                                query: q,
                                path: "searchTags",
                                score: { boost: { value: 3 } }
                            }
                        }
                    ],
                    minimumShouldMatch: 1
                }
            }
        }];

        if (category && category !== "all") {
            pipeline.push({ $match: { category: new RegExp(category, 'i') } });
        }

        if (sort === "price-low") {
            pipeline.push({ $sort: { price: 1 } });
        } else if (sort === "price-high") {
            pipeline.push({ $sort: { price: -1 } });
        } else if (sort === "rating") {
            pipeline.push({ $sort: { "rating.rate": -1 } });
        } else {
            pipeline.push({ $sort: { score: { $meta: "searchScore" } } });
        }

        const [products, totalArr] = await Promise.all([
            total_products.aggregate([...pipeline, { $skip: skip }, { $limit: limit }]),
            total_products.aggregate([...pipeline, { $count: "total" }])
        ]);

        const total = totalArr[0]?.total || 0;
        const result = {
            products,
            total,
            page,
            last_page: Math.ceil(total / limit),
            hasMore: skip + limit < total,
            limit
        };

        cache.set(ck, result, 60);
        res.json(result);
    } catch (err) {
        console.error("Search error:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/product/:id', requireApiKey, async (req, res) => {
    try {
        const { id } = req.params;
        const ck = `prod_${id}`;
        const hit = cache.get(ck);
        if (hit) return res.json(hit);
        const filter = makeFilter(id);
        if (!filter) {
            return res.status(404).json({ error: 'Not found' });
        }
        const product = await total_products.findOne(filter).lean();
        if (!product) {
            return res.status(404).json({ error: 'Not found' });
        }
        cache.set(ck, product, 300);
        res.json(product);
    } catch (err) {
        console.error('[/product/:id]', err.message);
        res.status(500).json({ error: 'Server error', detail: err.message });
    }
});

app.get('/product/:id/related', requireApiKey, async (req, res) => {
    try {
        const { id } = req.params;
        const page = Math.max(1, parseInt(req.query.sameCatPage) || 1);
        const limit = Math.min(40, parseInt(req.query.sameCatLimit) || 20);
        const skip = (page - 1) * limit;
        const ck = `related_${id}_p${page}_l${limit}`;
        const hit = cache.get(ck);
        if (hit) return res.json(hit);
        const filter = makeFilter(id);
        if (!filter) {
            return res.status(404).json({ error: 'Not found' });
        }
        const found = await total_products.findOne(filter, '_id id category').lean();
        if (!found) {
            return res.status(404).json({ error: 'Not found' });
        }
        const catFilter = { category: found.category };
        const selfIdStr = String(found._id);
        const [sameCat, relatedRaw, sameCatTotal] = await Promise.all([
            total_products.find(catFilter).select(CARD_SELECT).skip(skip).limit(limit).lean(),
            total_products.find(catFilter).select(CARD_SELECT).limit(9).lean(),
            total_products.countDocuments(catFilter),
        ]);
        const related = relatedRaw.filter(p => String(p._id) !== selfIdStr).slice(0, 8);
        const payload = {
            sameCat,
            related,
            sameCatTotal,
            sameCatPage: page,
            sameCatPages: Math.ceil(sameCatTotal / limit),
            sameCatLimit: limit
        };
        cache.set(ck, payload, 180);
        res.json(payload);
    } catch (err) {
        console.error('[/product/:id/related]', err.message);
        res.status(500).json({ error: 'Server error', detail: err.message });
    }
});

app.get('/shopdata/categories', requireApiKey, async (req, res) => {
    try {
        const cats = await total_products.distinct("category");
        res.json({ categories: cats.filter(Boolean).sort() });
    } catch (err) {
        console.error('Categories error:', err);
        res.status(500).json({ error: 'Categories pawa jayni' });
    }
});

// ─── Order Routes ───
// ⚠️ এখন থেকে order create হলেই আর কোনো courier-এ auto-book হয় না।
// Order শুধু "pending_confirmation" status-এ DB-তে save হয়, admin panel
// থেকে confirm করলে তারপর Paperfly-তে dynamic pickup সহ বুক হয়
// (নিচে /admin/orders/:orderId/confirm রুট দেখুন)।

app.post('/orders', requireApiKey, async (req, res) => {
    try {
        const newData = new orderdata({
            ...req.body,
            courier_status: 'pending_confirmation',
        });
        await newData.save();
        delCache('all_orders');
        res.status(201).json(newData);

        const { email, title, name, image, price, quantity, size, category, address, productId } = req.body;
        const emailParams = {
            heading: 'Order Confirmed!',
            subheading: `প্রিয় ${name || 'customer'}, আপনার অর্ডারটি সফলভাবে গ্রহণ করা হয়েছে।`,
            id: productId,
            title,
            image: toCloudinaryUrl(image),
            price, quantity, size, category, address,
            email,
            showReview: true,
        };
        sendProductEmail(
            email,
            buildProductEmailHtml(emailParams),
            `Order Confirmed - ${title || 'ONE-SHOP'}`,
            buildProductEmailText(emailParams)
        );
    } catch (err) {
        console.error('Orders save error:', err);
        res.status(500).json({ error: 'Order save error' });
    }
});

app.get('/orders', requireApiKey, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 4;
        const skip = (page - 1) * limit;
        const email = (req.query.email || '').trim();
        // ⚠️ checkout form-এর বিভিন্ন version-এ buyer email কখনো "email" ফিল্ডে,
        // কখনো "Byer_email" (typo সহ) ফিল্ডে সেভ হয়েছে — তাই দুটো ফিল্ড নামই
        // চেক করা হচ্ছে, নাহলে পুরনো/নতুন কিছু অর্ডার filter থেকে বাদ পড়ে যাবে
        const filter = email ? { $or: [{ email }, { Byer_email: email }] } : {};

        const cacheKeyName = `orders_${email || 'all'}_page_${page}_limit_${limit}`;
        const hit = getCache(cacheKeyName);
        if (hit) return res.json(hit);

        const [orders, total] = await Promise.all([
            orderdata.find(filter).sort({ _id: -1 }).skip(skip).limit(limit),
            orderdata.countDocuments(filter),
        ]);
        const result = { orders, total, hasMore: skip + limit < total };
        setCache(cacheKeyName, result, 60);
        res.json(result);
    } catch (err) {
        console.error('Orders get error:', err);
        res.status(500).json({ error: 'Orders pawa jayni' });
    }
});

// ─── Auth Data Routes ───

// ── GOOGLE OAUTH LOGIN — এখন token ফেরত দেয় ────────────────────────
app.post('/logindata', requireApiKey, async (req, res) => {
    try {
        const { email, name, picture, googleId } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, error: 'Valid email দাও' });
        }
        let userDoc = await userlogindata.findOne({ email });
        let isNew = false;
        if (!userDoc) {
            userDoc = new userlogindata({ email, name, picture, googleId });
            await userDoc.save();
            isNew = true;
        }
        const token = generateUserToken(userDoc);
        res.status(isNew ? 201 : 200).json({
            success: true,
            message: isNew ? 'Saved' : 'User already exists',
            token,
            data: userDoc,
            isNew,
        });
    } catch (err) {
        if (err.code === 11000) {
            // race condition — একসাথে দুইবার রিকোয়েস্ট এলে, existing user টা fetch করে token দিয়ে দিন
            const existing = await userlogindata.findOne({ email: req.body.email });
            const token = existing ? generateUserToken(existing) : null;
            return res.status(200).json({ success: true, message: 'User already exists', token, data: existing, isNew: false });
        }
        console.error('Login data save error:', err);
        res.status(500).json({ success: false, error: 'Save error' });
    }
});

// ── EMAIL/PASSWORD REGISTER — এখন token ফেরত দেয় ───────────────────
app.post('/loginnewdata', requireApiKey, authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, error: 'Valid email দাও' });
        }
        if (!password || password.length < 6) {
            return res.status(400).json({ success: false, error: 'Password ৬ character' });
        }
        const existing = await userlogindata.findOne({ email });
        if (existing) {
            const token = generateUserToken(existing);
            return res.status(200).json({ success: true, message: 'User already exists', token, data: existing, isNew: false });
        }
        const hashed = await hashPassword(password);
        const newData = new userlogindata({ email, password: hashed });
        await newData.save();
        const token = generateUserToken(newData);
        res.status(201).json({ success: true, message: 'Saved', token, data: newData, isNew: true });
    } catch (err) {
        if (err.code === 11000) {
            return res.status(200).json({ success: true, message: 'User already exists', isNew: false });
        }
        console.error('Login new data save error:', err);
        res.status(500).json({ success: false, error: 'Save error' });
    }
});


app.get('/loginnewdata', requireApiKey, async (req, res) => {
    try {
        const { email } = req.query;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, error: 'Valid email দাও' });
        }
        const key = `user_${email}`;
        const hit = getCache(key);
        if (hit) {
            return res.status(200).json({ success: true, data: hit });
        }
        const user = await userlogindata.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        setCache(key, user, 120);
        res.status(200).json({ success: true, data: user });
    } catch (err) {
        console.error('Login new data get error:', err);
        res.status(500).json({ success: false, error: 'Fetch error' });
    }
});

// ── EMAIL/PASSWORD LOGIN — এখন token ফেরত দেয় ──────────────────────
app.post('/relogin', requireApiKey, authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, error: 'Valid email দাও' });
        }
        const user = await userlogindata.findOne({ email });
        if (!user) {
            return res.json({ success: false });
        }
        if (password) {
            const ok = await verifyAndMaybeMigratePassword(password, user);
            if (!ok) return res.json({ success: false });
        }
        const token = generateUserToken(user);
        res.json({ success: true, token, user });
    } catch (err) {
        console.error('Relogin error:', err);
        res.status(500).json({ success: false, error: 'Login error' });
    }
});

// ─── Cart Routes ───

app.post('/cartdata', requireApiKey, async (req, res) => {
    try {
        const { productId, email } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ error: 'Valid email দাও' });
        }
        await cartitem.deleteOne({ productId, email });
        const newCartItem = new cartitem(req.body);
        await newCartItem.save();
        delCache(`cart_${email}`);
        res.status(201).json(newCartItem);

        const { title, image, price, quantity, size, category } = req.body;
        const emailParams = {
            heading: 'Cart-এ যোগ হয়েছে',
            subheading: 'আপনার পছন্দের প্রোডাক্টটি cart-এ যোগ হয়েছে।',
            id: productId,
            title,
            image: toCloudinaryUrl(image),
            price, quantity, size, category,
            email,
            showReview: false,
        };
        sendProductEmail(
            email,
            buildProductEmailHtml(emailParams),
            `Cart Updated - ${title || 'ONE-SHOP'}`,
            buildProductEmailText(emailParams)
        );
    } catch (err) {
        console.error('Cart data save error:', err);
        res.status(500).json({ error: 'Cart error' });
    }
});

app.post('/getcartdata', requireApiKey, async (req, res) => {
    const { email, page = 1, limit = 4 } = req.body;
    if (!email || !isValidEmail(email)) {
        return res.status(400).json({ success: false, error: 'Valid email দাও' });
    }
    try {
        const skip = (page - 1) * limit;
        const [cartItems, total] = await Promise.all([
            cartitem.find({ email }).sort({ _id: -1 }).skip(skip).limit(limit).lean(),
            cartitem.countDocuments({ email }),
        ]);
        const result = { success: true, cartItems, total, hasMore: skip + cartItems.length < total };
        res.json(result);
    } catch (err) {
        console.error('Get cart data error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── Review Routes ───

app.get('/reviewdata/:id', requireApiKey, async (req, res) => {
    try {
        const idParam = req.params.id;
        if (isNaN(Number(idParam))) {
            return res.status(400).json({ success: false, message: 'Invalid product id' });
        }
        const key = `review_${idParam}`;
        const hit = getCache(key);
        if (hit) {
            return res.status(200).json({ success: true, data: hit });
        }
        const product = await ShopModel.find({ productId: Number(idParam) });
        if (!product.length) {
            return res.status(404).json({ success: false, message: 'Product not found' });
        }
        setCache(key, product, 60);
        res.status(200).json({ success: true, data: product });
    } catch (err) {
        console.error('Review data error:', err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

app.post('/reviews', requireApiKey, async (req, res) => {
    try {
        const { productId, email, comment, imageUrl, rating } = req.body;

        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ error: 'Valid email দাও' });
        }
        if (!comment || String(comment).trim().length < 1) {
            return res.status(400).json({ error: 'Comment দাও' });
        }

        let ratingValue = null;
        if (rating !== undefined && rating !== null && rating !== '') {
            ratingValue = Number(rating);
            if (isNaN(ratingValue) || ratingValue < 1 || ratingValue > 5) {
                return res.status(400).json({ error: 'Rating 1 থেকে 5 এর মধ্যে হতে হবে' });
            }
        }

        const product = await ShopModel.create({
            productId: Number(productId),
            email,
            comment: String(comment).substring(0, 1000),
            imageUrl: imageUrl || null,
            rating: ratingValue,
        });

        delCache(`review_${productId}`);
        res.status(201).json({ success: true, message: 'রিভিউ পোস্ট হয়েছে!', data: product });
    } catch (err) {
        console.error('Review save error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/reviews/quick-rate', async (req, res) => {
    try {
        const { productId, email, rating, token } = req.query;

        if (!productId || !email || !isValidEmail(email)) {
            return res.status(400).send('<h2>❌ Invalid request</h2>');
        }

        const expectedToken = makeReviewToken(productId, email);
        if (token !== expectedToken) {
            return res.status(403).send('<h2>❌ Invalid or expired link</h2>');
        }

        const ratingValue = Number(rating);
        if (isNaN(ratingValue) || ratingValue < 1 || ratingValue > 5) {
            return res.status(400).send('<h2>❌ Invalid rating</h2>');
        }

        const existing = await ShopModel.findOne({ productId: Number(productId), email });
        if (existing) {
            existing.rating = ratingValue;
            await existing.save();
        } else {
            await ShopModel.create({
                productId: Number(productId),
                email,
                comment: '(Quick rating from email)',
                rating: ratingValue,
            });
        }
        delCache(`review_${productId}`);

        res.send(`
        <div style="font-family:Arial;max-width:400px;margin:60px auto;text-align:center;padding:32px;background:#0f172a;color:#f1f5f9;border-radius:12px;">
            <h2 style="color:#22c55e;">ধন্যবাদ! ⭐ ${ratingValue}/5 রেটিং দেওয়া হয়েছে</h2>
            <p style="color:#94a3b8;">চাইলে বিস্তারিত মতামত লিখতে <a href="https://oneshop.pre.bd/product/${productId}" style="color:#3b82f6;">এখানে</a> ক্লিক করো।</p>
        </div>`);
    } catch (err) {
        console.error('Quick rate error:', err);
        res.status(500).send('<h2>Server error</h2>');
    }
});

// ─── Location Routes ───

app.post('/getuserlocationdata', requireApiKey, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ error: 'Valid email দাও' });
        }
        const key = `location_${email}`;
        const hit = getCache(key);
        if (hit) {
            return res.status(200).json(hit);
        }
        const existing = await locationdata.findOne({ email });
        if (existing) {
            setCache(key, existing, 300);
            return res.status(200).json(existing);
        }
        const newData = new locationdata(req.body);
        await newData.save();
        setCache(key, newData, 300);
        res.status(201).json(newData);
    } catch (err) {
        console.error('Get user location data error:', err);
        res.status(500).json({ error: 'Location error' });
    }
});

app.get('/userlocation', requireApiKey, async (req, res) => {
    try {
        const { email } = req.query;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ error: 'Valid email দাও' });
        }
        const key = `location_${email}`;
        const hit = getCache(key);
        if (hit) {
            return res.status(200).json(hit);
        }
        const data = await locationdata.findOne({ email });
        if (data) {
            setCache(key, data, 300);
            return res.status(200).json(data);
        }
        res.status(404).json({ error: 'Not found' });
    } catch (err) {
        console.error('User location get error:', err);
        res.status(500).json({ error: 'Error' });
    }
});

app.post('/userlocation', requireApiKey, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ error: 'Valid email দাও' });
        }
        const existing = await locationdata.findOne({ email });
        if (existing) {
            return res.status(400).json({ error: 'এই email দিয়ে আগেই address আছে!' });
        }
        const newData = new locationdata(req.body);
        await newData.save();
        delCache(`location_${email}`);
        res.status(201).json(newData);
    } catch (err) {
        console.error('User location save error:', err);
        res.status(500).json({ error: 'Address save error' });
    }
});

app.put('/userlocation', requireApiKey, async (req, res) => {
    try {
        const { email } = req.query;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ error: 'Valid email দাও' });
        }
        const updated = await locationdata.findOneAndUpdate(
            { email },
            { $set: req.body },
            { new: true, runValidators: true }
        );
        if (!updated) {
            return res.status(404).json({ error: 'Address পাওয়া যায়নি' });
        }
        delCache(`location_${email}`);
        res.json(updated);
    } catch (err) {
        console.error('User location update error:', err);
        res.status(500).json({ error: 'Update error' });
    }
});

app.delete('/userlocation', requireApiKey, async (req, res) => {
    try {
        const { email } = req.query;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ error: 'Valid email দাও' });
        }
        const deleted = await locationdata.findOneAndDelete({ email });
        if (!deleted) {
            return res.status(404).json({ error: 'Address পাওয়া যায়নি' });
        }
        delCache(`location_${email}`);
        res.json({ success: true, message: 'Address delete হয়েছে' });
    } catch (err) {
        console.error('User location delete error:', err);
        res.status(500).json({ error: 'Delete error' });
    }
});

// ════════════════════════════════════════════════════════════
// 👑 ADMIN: সব seller-এর সব অর্ডার — কোনো email filter নেই,
// শুধু requireAdmin (JWT + isAdmin===true) দিয়ে protected
// ════════════════════════════════════════════════════════════

// ── ADMIN: সব অর্ডার (pagination সহ, কোনো seller filter নেই) ─────────
app.get('/admin/orders', requireAdmin, async (req, res) => {
    try {
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(50, parseInt(req.query.limit) || 4);
        const skip = (page - 1) * limit;
        const status = (req.query.status || '').trim(); // optional filter

        const filter = {};
        if (status) {
            filter.courier_status = status;
        }

        const [orders, total] = await Promise.all([
            orderdata.find(filter).sort({ _id: -1 }).skip(skip).limit(limit).lean(),
            orderdata.countDocuments(filter),
        ]);

        res.json({ success: true, orders, total, page, hasMore: skip + orders.length < total });
    } catch (err) {
        console.error('❌ admin/orders:', err);
        res.status(500).json({ success: false, error: 'Orders পাওয়া যায়নি' });
    }
});

// ── ADMIN: সব seller মিলিয়ে status summary (কয়টা delivered / return ইত্যাদি) ──
app.get('/admin/order-status-summary', requireAdmin, async (req, res) => {
    try {
        const grouped = await orderdata.aggregate([
            {
                $group: {
                    _id: { $ifNull: ['$courier_status', 'processing'] },
                    count: { $sum: 1 },
                },
            },
        ]);

        const summary = {
            pending_confirmation: 0,
            processing: 0,
            in_transit: 0,
            delivered: 0,
            partial_delivered: 0,
            returned: 0,
            cancelled: 0,
        };
        let total = 0;
        for (const g of grouped) {
            const key = summary.hasOwnProperty(g._id) ? g._id : 'processing';
            summary[key] += g.count;
            total += g.count;
        }

        res.json({ success: true, summary, total });
    } catch (err) {
        console.error('❌ admin/order-status-summary:', err);
        res.status(500).json({ success: false, error: 'Summary পাওয়া যায়নি' });
    }
});

// ── ADMIN: সব seller মিলিয়ে delivered order-এর মোট বিক্রি, প্ল্যাটফর্ম কমিশন
//    (৫%), আর সেলারদের মোট প্রাপ্য (৯৫%) — Orders ট্যাবের উপরে দেখানোর জন্য ──
app.get('/admin/delivered-summary', requireAdmin, async (req, res) => {
    try {
        const result = await orderdata.aggregate([
            { $match: { courier_status: 'delivered' } },
            {
                $group: {
                    _id: null,
                    totalAmount: {
                        $sum: { $multiply: [{ $ifNull: ['$price', 0] }, { $ifNull: ['$quantity', 1] }] },
                    },
                    totalOrders: { $sum: 1 },
                },
            },
        ]);

        const totalAmount = result[0]?.totalAmount || 0;
        const totalOrders = result[0]?.totalOrders || 0;
        const platformProfit = Math.round(totalAmount * PLATFORM_COMMISSION_RATE * 100) / 100;
        const sellerPayoutTotal = Math.round((totalAmount - platformProfit) * 100) / 100;

        res.json({
            success: true,
            totalAmount, // মূল/original মোট বিক্রি (কমিশন কাটার আগে)
            totalOrders,
            platformProfit, // আমাদের মোট ৫% লাভ
            sellerPayoutTotal, // সব সেলার মিলিয়ে মোট প্রাপ্য (৯৫%)
            commissionRate: PLATFORM_COMMISSION_RATE,
        });
    } catch (err) {
        console.error('❌ admin/delivered-summary:', err);
        res.status(500).json({ success: false, error: 'Delivered summary পাওয়া যায়নি' });
    }
});

// ── ADMIN: seller অনুযায়ী breakdown (কোন সেলারের কয়টা order কোন status-এ) ──
app.get('/admin/order-status-by-seller', requireAdmin, async (req, res) => {
    try {
        const pipeline = [
            {
                $lookup: {
                    from: 'total_product',
                    localField: 'productId',
                    foreignField: 'id',
                    as: 'productInfo',
                },
            },
            { $unwind: { path: '$productInfo', preserveNullAndEmptyArrays: true } },
            {
                $group: {
                    _id: {
                        seller_email: { $ifNull: ['$productInfo.seller_email', 'unknown'] },
                        status: { $ifNull: ['$courier_status', 'processing'] },
                    },
                    count: { $sum: 1 },
                },
            },
            {
                $group: {
                    _id: '$_id.seller_email',
                    statuses: { $push: { status: '$_id.status', count: '$count' } },
                    total: { $sum: '$count' },
                },
            },
            { $sort: { total: -1 } },
        ];

        const result = await orderdata.aggregate(pipeline);
        res.json({ success: true, sellers: result });
    } catch (err) {
        console.error('❌ admin/order-status-by-seller:', err);
        res.status(500).json({ success: false, error: 'Breakdown পাওয়া যায়নি' });
    }
});

// ════════════════════════════════════════════════════════════
// 📦 ADMIN: Paperfly order confirm/booking — dynamic pickup address
// ════════════════════════════════════════════════════════════
//
// এখানেই মূল ফ্লো: user order দিলে শুধু DB-তে "pending_confirmation"
// অবস্থায় জমা হয়। Admin panel থেকে এই রুট কল করলে —
//   1) order-এর productId দিয়ে আসল প্রোডাক্ট বের করা হয়
//   2) প্রোডাক্টের seller_email দিয়ে সেই seller-এর Store বের করা হয়
//   3) Store-এর paperfly_store_name ব্যবহার করে Paperfly-তে order create হয়
//   4) response থেকে tracking_number সেভ করে courier_status = "processing" হয়ে যায়

app.post('/admin/orders/:orderId/confirm', requireAdmin, async (req, res) => {
    try {
        const { orderId } = req.params;

        const order = await orderdata.findById(orderId);
        if (!order) {
            return res.status(404).json({ success: false, error: 'Order পাওয়া যায়নি' });
        }
        if (order.paperfly_order_ref) {
            return res.status(400).json({
                success: false,
                error: 'এই order আগেই confirm/book করা হয়েছে',
                tracking_number: order.paperfly_tracking_number,
            });
        }
        const rawPhone = getOrderPhone(order);
        if (!rawPhone) {
            return res.status(400).json({ success: false, error: 'Order-এ কাস্টমারের phone নেই' });
        }
        // ⚠️ শুধু phone আছে কিনা না, Paperfly-এর ফরম্যাটে normalize হয় কিনা সেটাও
        // এখানেই চেক করা হচ্ছে — নাহলে Paperfly থেকে generic "Invalid Receiver
        // phone number" error আসে, যেটা admin panel-এ debug করা কঠিন।
        const normalizedPhoneCheck = normalizeBdPhone(rawPhone);
        if (!normalizedPhoneCheck) {
            return res.status(400).json({
                success: false,
                error: `Order-এর phone নম্বর সঠিক ফরম্যাটে নেই ("${rawPhone}") — ১১ ডিজিটের বাংলাদেশি নম্বর হতে হবে (01XXXXXXXXX)। order-এর phone ফিল্ড ঠিক করে আবার confirm করুন।`,
            });
        }
        if (!order.address) {
            return res.status(400).json({ success: false, error: 'Order-এ ঠিকানা নেই' });
        }

        // ── আসল প্রোডাক্ট বের করে সঠিক seller_email নিশ্চিত করা (blindly trust না করে) ──
        const product = await total_products.findOne({ id: order.productId }).lean();
        if (!product || !product.seller_email) {
            return res.status(400).json({ success: false, error: 'এই order-এর প্রোডাক্ট/সেলার খুঁজে পাওয়া যায়নি' });
        }

        // ── সেলারের Store বের করা — এখানেই dynamic pickup address-এর মূল লজিক ──
        const store = await Store.findOne({ email: product.seller_email }).lean();
        if (!store) {
            return res.status(400).json({ success: false, error: 'এই সেলারের কোনো store পাওয়া যায়নি' });
        }
        if (!store.paperfly_store_name) {
            return res.status(400).json({
                success: false,
                error: 'এই সেলারের জন্য Paperfly store name সেট করা হয়নি। প্রথমে Paperfly merchant panel-এ এই সেলারের ঠিকানা দিয়ে একটা Store বানিয়ে, তারপর PUT /admin/store/:storeId/paperfly-name দিয়ে সেট করুন।',
                seller_email: product.seller_email,
                store_id: store._id,
            });
        }

        const merchantOrderReference = `ORDER_${order._id}`;
        const payload = buildPaperflyPayload(order, store.paperfly_store_name, merchantOrderReference);

        const result = await paperflyRequest('/merchant/api/service/new_order_v2.php', payload);

        if (!result?.success?.tracking_number) {
            return res.status(502).json({ success: false, error: 'Paperfly থেকে tracking number পাওয়া যায়নি', raw: result });
        }

        order.paperfly_order_ref = merchantOrderReference;
        order.paperfly_tracking_number = result.success.tracking_number;
        order.paperfly_tracking_barcode = result.success.tracking_barcode;
        order.courier = 'paperfly';
        order.courier_status = 'processing';
        order.pickup_store_name = store.paperfly_store_name; // reference রাখার জন্য
        order.seller_email = product.seller_email; // seller-filtered queries-এর জন্য নিশ্চিত করে রাখা
        order.admin_confirmed = true;
        order.admin_confirmed_at = new Date();
        await order.save();

        delCache('all_orders');

        res.status(201).json({ success: true, order, paperfly: result.success });
    } catch (err) {
        console.error('❌ admin/orders/confirm:', err.message);
        res.status(500).json({ success: false, error: err.message || 'Booking failed' });
    }
});

// ── ADMIN: একসাথে একাধিক order confirm করা (sequential loop — Paperfly-তে bulk endpoint নেই) ──
app.post('/admin/orders/bulk-confirm', requireAdmin, async (req, res) => {
    try {
        const { orderIds } = req.body;
        if (!Array.isArray(orderIds) || orderIds.length === 0) {
            return res.status(400).json({ success: false, error: 'orderIds array দাও' });
        }

        const results = [];
        for (const orderId of orderIds) {
            try {
                const order = await orderdata.findById(orderId);
                if (!order || order.paperfly_order_ref) {
                    results.push({ orderId, success: false, error: 'পাওয়া যায়নি অথবা আগেই বুক করা' });
                    continue;
                }
                const rawPhoneBulk = getOrderPhone(order);
                if (!rawPhoneBulk || !order.address) {
                    results.push({ orderId, success: false, error: 'phone/address নেই' });
                    continue;
                }
                if (!normalizeBdPhone(rawPhoneBulk)) {
                    results.push({ orderId, success: false, error: `ভুল ফরম্যাটের phone ("${rawPhoneBulk}")` });
                    continue;
                }

                const product = await total_products.findOne({ id: order.productId }).lean();
                const store = product ? await Store.findOne({ email: product.seller_email }).lean() : null;

                if (!store?.paperfly_store_name) {
                    results.push({ orderId, success: false, error: 'সেলারের Paperfly store name সেট নেই' });
                    continue;
                }

                const merchantOrderReference = `ORDER_${order._id}`;
                const payload = buildPaperflyPayload(order, store.paperfly_store_name, merchantOrderReference);
                const result = await paperflyRequest('/merchant/api/service/new_order_v2.php', payload);

                if (!result?.success?.tracking_number) {
                    results.push({ orderId, success: false, error: 'Paperfly response invalid' });
                    continue;
                }

                order.paperfly_order_ref = merchantOrderReference;
                order.paperfly_tracking_number = result.success.tracking_number;
                order.paperfly_tracking_barcode = result.success.tracking_barcode;
                order.courier = 'paperfly';
                order.courier_status = 'processing';
                order.pickup_store_name = store.paperfly_store_name;
                order.seller_email = product.seller_email;
                order.admin_confirmed = true;
                order.admin_confirmed_at = new Date();
                await order.save();

                results.push({ orderId, success: true, tracking_number: result.success.tracking_number });
            } catch (innerErr) {
                results.push({ orderId, success: false, error: innerErr.message });
            }
        }

        delCache('all_orders');
        const booked = results.filter(r => r.success).length;
        res.status(201).json({ success: true, booked, requested: orderIds.length, results });
    } catch (err) {
        console.error('❌ admin/orders/bulk-confirm:', err.message);
        res.status(500).json({ success: false, error: err.message || 'Bulk confirm failed' });
    }
});

// ── ADMIN: order cancel করা (Paperfly-তে বুক হওয়ার পর) ──────────────
app.post('/admin/orders/:orderId/cancel-paperfly', requireAdmin, async (req, res) => {
    try {
        const { orderId } = req.params;
        const order = await orderdata.findById(orderId);
        if (!order) {
            return res.status(404).json({ success: false, error: 'Order পাওয়া যায়নি' });
        }
        if (!order.paperfly_order_ref) {
            return res.status(400).json({ success: false, error: 'এই order এখনো Paperfly-তে বুক হয়নি' });
        }

        const result = await paperflyRequest('/api/v1/cancel-order', {
            order_id: order.paperfly_order_ref,
        });

        order.courier_status = 'cancelled';
        await order.save();

        delCache('all_orders');
        res.json({ success: true, order, paperfly: result });
    } catch (err) {
        console.error('❌ admin/orders/cancel-paperfly:', err.message);
        res.status(500).json({ success: false, error: err.message || 'Cancel failed' });
    }
});

// ════════════════════════════════════════════════════════════
// 🔄 STATUS SYNC — processing → delivered/cancelled ইত্যাদিতে বদলানোর জায়গা
// ════════════════════════════════════════════════════════════
//
// দুইভাবে sync হয়:
//  1) ম্যানুয়াল: কেউ (admin/seller/customer) নির্দিষ্ট order-এর status GET করলে,
//     তখনই Paperfly থেকে freshly টেনে DB write-back হয় (নিচের GET রুট)
//  2) অটোমেটিক: নিচের setInterval background job প্রতি ১০ মিনিটে সব
//     "pending" (delivered/cancelled/returned নয় এমন) order-এর status
//     Paperfly থেকে টেনে DB আপডেট করে — admin panel না খুললেও status বদলে যায়

// ── PUBLIC-ISH: order-এর Paperfly delivery status দেখা (internal order _id দিয়ে) ──
app.get('/courier/paperfly/status/:orderId', requireApiKey, async (req, res) => {
    try {
        const { orderId } = req.params;
        const order = await orderdata.findById(orderId).lean();
        if (!order) {
            return res.status(404).json({ success: false, error: 'Order পাওয়া যায়নি' });
        }

        if (!order.paperfly_order_ref) {
            return res.json({ success: true, status: order.courier_status || 'pending_confirmation', message: 'এখনো admin confirm করেনি' });
        }

        const ck = `paperfly_status_${order.paperfly_order_ref}`;
        const cached = getCache(ck);
        if (cached) return res.json(cached);

        const normalized = await syncOnePaperflyOrderStatus(order);

        const payload = {
            success: true,
            status: normalized,
            tracking_number: order.paperfly_tracking_number || null,
        };
        setCache(ck, payload, 120);

        res.json(payload);
    } catch (err) {
        console.error('❌ courier/paperfly/status:', err.message);
        res.status(500).json({ success: false, error: 'Status পাওয়া যায়নি' });
    }
});

// ── ADMIN: একটা নির্দিষ্ট order-এর status ম্যানুয়ালি refresh করা ─────
app.post('/admin/orders/:orderId/sync-status', requireAdmin, async (req, res) => {
    try {
        const { orderId } = req.params;
        const order = await orderdata.findById(orderId);
        if (!order) {
            return res.status(404).json({ success: false, error: 'Order পাওয়া যায়নি' });
        }
        const normalized = await syncOnePaperflyOrderStatus(order);
        delCache('all_orders');
        res.json({ success: true, status: normalized });
    } catch (err) {
        console.error('❌ admin/orders/sync-status:', err.message);
        res.status(500).json({ success: false, error: err.message || 'Sync failed' });
    }
});

// ── ADMIN: সব "চলমান" order (booked কিন্তু delivered/cancelled/returned না) একসাথে sync ──
app.post('/admin/orders/sync-all', requireAdmin, async (req, res) => {
    try {
        const pending = await orderdata.find({
            paperfly_order_ref: { $exists: true, $ne: null },
            courier_status: { $nin: ['delivered', 'cancelled', 'returned'] },
        }).limit(300); // একসাথে অতিরিক্ত API কল এড়াতে একটা সেফ লিমিট

        const results = await syncManyPaperflyOrders(pending);
        delCache('all_orders');

        const updated = results.filter(r => r.success).length;
        res.json({ success: true, checked: pending.length, updated, results });
    } catch (err) {
        console.error('❌ admin/orders/sync-all:', err.message);
        res.status(500).json({ success: false, error: err.message || 'Sync failed' });
    }
});

// ── 🔁 Background auto-sync — প্রতি ১০ মিনিটে চলমান সব order-এর status refresh করে ──
// admin panel খোলা না থাকলেও processing → delivered/cancelled/returned আপডেট হতে থাকবে
const PAPERFLY_SYNC_INTERVAL_MS = 10 * 60 * 1000;
setInterval(async () => {
    try {
        if (!PAPERFLY_USERNAME || !PAPERFLY_PASSWORD || !PAPERFLY_KEY) return; // credentials না থাকলে skip

        const pending = await orderdata.find({
            paperfly_order_ref: { $exists: true, $ne: null },
            courier_status: { $nin: ['delivered', 'cancelled', 'returned'] },
        }).limit(300);

        if (pending.length === 0) return;

        const results = await syncManyPaperflyOrders(pending);
        const updated = results.filter(r => r.success).length;
        console.log(`🔄 Auto-sync: ${pending.length} টা order চেক করা হলো, ${updated} টা সফল`);
    } catch (err) {
        console.error('❌ Background paperfly sync failed:', err.message);
    }
}, PAPERFLY_SYNC_INTERVAL_MS);

// ════════════════════════════════════════════════════════════
// 🏪 ADMIN: Store — সব seller-এর store লিস্ট + Paperfly store name সেট করা
// ════════════════════════════════════════════════════════════
//
// Paperfly-তে API দিয়ে Store তৈরি করা যায় না (ম্যানুয়ালি Paperfly merchant
// panel-এ গিয়ে বানাতে হয়) — তাই admin এখানে শুধু সেই ম্যানুয়ালি তৈরি করা
// store-এর "নাম"টা আমাদের DB-তে সেলারের Store doc-এর সাথে লিংক করে দেয়।

// ── ADMIN: সব seller-এর store লিস্ট (কোনটার paperfly_store_name সেট নেই বোঝার জন্য)
//    + প্রতি সেলারের delivered order থেকে total বিক্রি, ৫% platform commission,
//    আর সেলারকে দেওয়ার মতো নেট payout — এই তিনটা হিসাবও একসাথে দেয় ──────
app.get('/admin/stores', requireAdmin, async (req, res) => {
    try {
        const stores = await Store.find({}).sort({ _id: -1 }).lean();

        // প্রতিটা delivered order-কে তার প্রোডাক্টের productId দিয়ে seller_email-এ
        // ম্যাপ করে, সেলার অনুযায়ী গ্রুপ করে total বিক্রি বের করা হচ্ছে।
        // (courier_status filter করা হয় — শুধু "delivered" মানে আসলে টাকা এসেছে,
        // pending/cancelled/returned এখানে ধরা হয় না।)
        const salesPipeline = [
            { $match: { courier_status: 'delivered' } },
            {
                $lookup: {
                    from: 'total_product',
                    localField: 'productId',
                    foreignField: 'id',
                    as: 'productInfo',
                },
            },
            { $unwind: '$productInfo' },
            {
                $group: {
                    _id: '$productInfo.seller_email',
                    totalAmount: {
                        $sum: { $multiply: [{ $ifNull: ['$price', 0] }, { $ifNull: ['$quantity', 1] }] },
                    },
                    deliveredOrders: { $sum: 1 },
                },
            },
        ];
        const salesResults = await orderdata.aggregate(salesPipeline);
        const salesByEmail = {};
        for (const r of salesResults) salesByEmail[r._id] = r;

        const storesWithSales = stores.map((store) => {
            const sales = salesByEmail[store.email];
            const totalAmount = sales?.totalAmount || 0;
            // ৫% আমাদের প্ল্যাটফর্মের কমিশন, বাকি ৯৫% সেলারের প্রাপ্য
            const platformProfit = Math.round(totalAmount * PLATFORM_COMMISSION_RATE * 100) / 100;
            const sellerPayout = Math.round((totalAmount - platformProfit) * 100) / 100;
            return {
                ...store,
                delivered_order_count: sales?.deliveredOrders || 0,
                delivered_total_amount: totalAmount, // মূল/original বিক্রির পরিমাণ (কমিশন কাটার আগে)
                platform_profit: platformProfit, // আমাদের ৫% লাভ
                seller_payout: sellerPayout, // সেলারকে যা দিতে হবে (৯৫%)
            };
        });

        res.json({ success: true, stores: storesWithSales, commission_rate: PLATFORM_COMMISSION_RATE });
    } catch (err) {
        console.error('❌ admin/stores:', err);
        res.status(500).json({ success: false, error: 'Store লিস্ট পাওয়া যায়নি' });
    }
});

// ── ADMIN: একটা seller-এর store-এ Paperfly store name সেট/আপডেট করা ──
app.put('/admin/store/:storeId/paperfly-name', requireAdmin, async (req, res) => {
    try {
        const { storeId } = req.params;
        const { paperfly_store_name, paperfly_address, paperfly_phone } = req.body;

        if (!paperfly_store_name || !String(paperfly_store_name).trim()) {
            return res.status(400).json({ success: false, error: 'paperfly_store_name দাও' });
        }

        // address/phone দেওয়া ঐচ্ছিক — শুধু reference/দেখানোর জন্য, Paperfly-কে
        // অর্ডার পাঠানোর সময় এই address কোথাও পাঠানো হয় না (কারণ Paperfly API-তে
        // এটার কোনো ফিল্ড নেই, শুধু storeName পাঠানো হয়) — এটা সেভ থাকে যাতে
        // admin panel-এ কে কোন ঠিকানার জন্য কোন Store বানিয়েছেন সেটা মনে রাখা যায়
        const update = { paperfly_store_name: String(paperfly_store_name).trim() };
        if (paperfly_address !== undefined) update.paperfly_address = String(paperfly_address).trim();
        if (paperfly_phone !== undefined) update.paperfly_phone = String(paperfly_phone).trim();

        const store = await Store.findByIdAndUpdate(
            storeId,
            { $set: update },
            { new: true }
        );
        if (!store) {
            return res.status(404).json({ success: false, error: 'Store পাওয়া যায়নি' });
        }

        res.json({ success: true, store, message: 'Paperfly store তথ্য সেট হয়েছে' });
    } catch (err) {
        console.error('❌ admin/store/paperfly-name:', err);
        res.status(500).json({ success: false, error: 'Paperfly store তথ্য সেট করা যায়নি' });
    }
});

// ════════════════════════════════════════════════════════════
// 🚚 SELLER: নিজের প্রোডাক্টের order status summary
// (delivered koita, return koita, ইত্যাদি) — email verify করে
// শুধুমাত্র seller-এর নিজের product-এর order-ই count হয়
// ════════════════════════════════════════════════════════════
//
// কেন $lookup দিয়ে করা হচ্ছে (সরাসরি orderdata.seller_email
// দিয়ে filter না করে)?
// → orderdata তৈরি হয় checkout থেকে (`/orders` POST), সেখানে
//   frontend যা পাঠায় সেটাই বসে যায়। কোনো bug/পুরনো order-এ
//   seller_email ভুল/অনুপস্থিত থাকলেও একজন seller অন্যের অর্ডার
//   দেখে ফেলার কোনো সুযোগ যেন না থাকে — তাই productId ধরে
//   total_products থেকে আসল seller_email verify করা হচ্ছে,
//   order doc-এ যা লেখা আছে সেটা blindly trust করা হচ্ছে না।

// ── SELLER: order status summary (কয়টা delivered / return / ইত্যাদি) ──
app.get('/seller/order-status-summary', requireSellerToken, async (req, res) => {
    try {
        const sellerEmail = req.seller.email; // token থেকে — spoof করা যায় না

        const pipeline = [
            // 1) order-এর productId দিয়ে আসল প্রোডাক্ট বের করে তার seller_email verify করা
            {
                $lookup: {
                    from: 'total_product', // total_products model যেই collection ব্যবহার করে
                    localField: 'productId',
                    foreignField: 'id',
                    as: 'productInfo',
                },
            },
            { $unwind: '$productInfo' },
            // 2) শুধু নিজের product-এর order রাখা — এখানেই আসল security check
            { $match: { 'productInfo.seller_email': sellerEmail } },
            // 3) courier_status অনুযায়ী গ্রুপ করে count
            {
                $group: {
                    _id: { $ifNull: ['$courier_status', 'pending_confirmation'] },
                    count: { $sum: 1 },
                },
            },
        ];

        const grouped = await orderdata.aggregate(pipeline);

        // সব সম্ভাব্য status 0 দিয়ে শুরু করে, তারপর actual count বসানো
        const summary = {
            pending_confirmation: 0,
            processing: 0,
            in_transit: 0,
            delivered: 0,
            partial_delivered: 0,
            returned: 0,
            cancelled: 0,
        };
        let total = 0;
        for (const g of grouped) {
            const key = summary.hasOwnProperty(g._id) ? g._id : 'processing';
            summary[key] += g.count;
            total += g.count;
        }

        res.json({ success: true, summary, total });
    } catch (err) {
        console.error('❌ seller/order-status-summary:', err);
        res.status(500).json({ success: false, error: 'Order status summary পাওয়া যায়নি' });
    }
});

// ── SELLER: নিজের delivered order-এর মোট বিক্রি, প্ল্যাটফর্ম কমিশন (৫%),
//    আর নিজের প্রাপ্য (৯৫%) — ownership check verified productId দিয়ে,
//    order doc-এর seller_email blindly trust করা হয় না ─────────────────
app.get('/seller/delivered-summary', requireSellerToken, async (req, res) => {
    try {
        const sellerEmail = req.seller.email; // token থেকে — spoof করা যায় না

        const pipeline = [
            {
                $lookup: {
                    from: 'total_product',
                    localField: 'productId',
                    foreignField: 'id',
                    as: 'productInfo',
                },
            },
            { $unwind: '$productInfo' },
            { $match: { 'productInfo.seller_email': sellerEmail } },
            { $match: { courier_status: 'delivered' } },
            {
                $group: {
                    _id: null,
                    totalAmount: {
                        $sum: { $multiply: [{ $ifNull: ['$price', 0] }, { $ifNull: ['$quantity', 1] }] },
                    },
                    totalOrders: { $sum: 1 },
                },
            },
        ];

        const result = await orderdata.aggregate(pipeline);
        const totalAmount = result[0]?.totalAmount || 0;
        const totalOrders = result[0]?.totalOrders || 0;
        const platformProfit = Math.round(totalAmount * PLATFORM_COMMISSION_RATE * 100) / 100;
        const sellerPayout = Math.round((totalAmount - platformProfit) * 100) / 100;

        res.json({
            success: true,
            totalAmount, // মূল/original মোট বিক্রি (কমিশন কাটার আগে)
            totalOrders,
            platformProfit, // প্ল্যাটফর্মের ৫% কমিশন
            sellerPayout, // সেলারের নিট প্রাপ্য (৯৫%)
            commissionRate: PLATFORM_COMMISSION_RATE,
        });
    } catch (err) {
        console.error('❌ seller/delivered-summary:', err);
        res.status(500).json({ success: false, error: 'Delivered summary পাওয়া যায়নি' });
    }
});

// ── SELLER: নির্দিষ্ট status-এর অর্ডার লিস্ট (verified, ownership-checked) ──
// যেমন: /seller/orders-by-status?status=delivered&page=1&limit=10
app.get('/seller/orders-by-status', requireSellerToken, async (req, res) => {
    try {
        const sellerEmail = req.seller.email;
        const status = (req.query.status || '').trim();
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(50, parseInt(req.query.limit) || 10);
        const skip = (page - 1) * limit;

        const basePipeline = [
            {
                $lookup: {
                    from: 'total_product',
                    localField: 'productId',
                    foreignField: 'id',
                    as: 'productInfo',
                },
            },
            { $unwind: '$productInfo' },
            { $match: { 'productInfo.seller_email': sellerEmail } },
        ];

        if (status) {
            basePipeline.push({
                $match: {
                    $expr: {
                        $eq: [{ $ifNull: ['$courier_status', 'pending_confirmation'] }, status],
                    },
                },
            });
        }

        const [orders, totalArr] = await Promise.all([
            orderdata.aggregate([
                ...basePipeline,
                { $sort: { _id: -1 } },
                { $skip: skip },
                { $limit: limit },
                { $project: { productInfo: 0 } }, // response হালকা রাখা
            ]),
            orderdata.aggregate([...basePipeline, { $count: 'total' }]),
        ]);

        const total = totalArr[0]?.total || 0;
        res.json({ success: true, orders, total, page, hasMore: skip + orders.length < total });
    } catch (err) {
        console.error('❌ seller/orders-by-status:', err);
        res.status(500).json({ success: false, error: 'অর্ডার লিস্ট পাওয়া যায়নি' });
    }
});

// ── SELLER: নিজের প্রোডাক্টের অর্ডার লিস্ট (সব status, pagination সহ) ──
app.get('/seller/my-orders', requireSellerToken, async (req, res) => {
    try {
        const sellerEmail = req.seller.email;
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(50, parseInt(req.query.limit) || 10);
        const skip = (page - 1) * limit;
        const courierStatus = (req.query.courier_status || '').trim();

        const basePipeline = [
            {
                $lookup: {
                    from: 'total_product',
                    localField: 'productId',
                    foreignField: 'id',
                    as: 'productInfo',
                },
            },
            { $unwind: '$productInfo' },
            { $match: { 'productInfo.seller_email': sellerEmail } },
        ];

        if (courierStatus) {
            basePipeline.push({
                $match: {
                    $expr: {
                        $eq: [{ $ifNull: ['$courier_status', 'pending_confirmation'] }, courierStatus],
                    },
                },
            });
        }

        const [orders, totalArr] = await Promise.all([
            orderdata.aggregate([
                ...basePipeline,
                { $sort: { _id: -1 } },
                { $skip: skip },
                { $limit: limit },
                { $project: { productInfo: 0 } },
            ]),
            orderdata.aggregate([...basePipeline, { $count: 'total' }]),
        ]);

        const total = totalArr[0]?.total || 0;
        res.json({ success: true, orders, total, page, hasMore: skip + orders.length < total });
    } catch (err) {
        console.error('❌ seller/my-orders:', err);
        res.status(500).json({ success: false, error: 'অর্ডার লিস্ট পাওয়া যায়নি' });
    }
});

// ── SELLER: নিজের প্রোডাক্ট এডিট করা (ownership check — শুধু নিজের product-ই এডিট করতে পারবে) ──
app.put('/seller/product/:id', requireSellerToken, async (req, res) => {
    try {
        const email = req.seller.email;
        const productIdNum = Number(req.params.id);
        if (isNaN(productIdNum)) {
            return res.status(400).json({ success: false, error: 'Invalid product id' });
        }

        const existing = await total_products.findOne({ id: productIdNum, seller_email: email });
        if (!existing) {
            return res.status(404).json({ success: false, error: 'প্রোডাক্ট পাওয়া যায়নি অথবা এটা তোমার নয়' });
        }

        const { name, category, price, sale_price, discount_percent, details, stock_status, images } = req.body;

        const update = {};
        if (name !== undefined && name.trim()) {
            update.name = name.trim();
            update.title = name.trim();
        }
        if (category !== undefined && category.trim()) update.category = category.trim();
        if (details !== undefined && details.trim()) update.details = details.trim();
        if (stock_status !== undefined) update.stock_status = stock_status;

        if (price !== undefined) {
            const numericPrice = Number(price);
            if (!Number.isFinite(numericPrice) || numericPrice <= 0) {
                return res.status(400).json({ success: false, error: 'সঠিক মূল্য দাও' });
            }
            update.price = numericPrice;
        }
        if (sale_price !== undefined) {
            const numericSalePrice = Number(sale_price);
            if (!Number.isFinite(numericSalePrice) || numericSalePrice <= 0) {
                return res.status(400).json({ success: false, error: 'সঠিক sale price দাও' });
            }
            update.sale_price = numericSalePrice;
        }
        update.discount_percent = discount_percent !== undefined && discount_percent !== null
            ? Number(discount_percent)
            : null;

        // ছবি বদলাতে চাইলে (frontend শুধু imagesDirty হলেই images পাঠায়)
        if (Array.isArray(images) && images.length > 0) {
            const cleanImages = images.filter(Boolean).slice(0, 6);
            const compressedImages = [];
            for (const img of cleanImages) {
                const compressed = await compressImageToTargetKB(img, 30);
                if (compressed) compressedImages.push(compressed);
            }
            if (compressedImages.length === 0) {
                return res.status(400).json({ success: false, error: 'ছবি প্রসেস করা যায়নি, আবার চেষ্টা করো' });
            }
            update.images = compressedImages;
            update.image = compressedImages[0];
            update.thumbnail_img = compressedImages[0];
        }

        const product = await total_products.findOneAndUpdate(
            { id: productIdNum, seller_email: email },
            { $set: update },
            { new: true }
        );

        delCache(`prod_${productIdNum}`);
        res.json({ success: true, product, message: 'প্রোডাক্ট আপডেট হয়েছে' });
    } catch (err) {
        console.error('❌ seller/product PUT:', err);
        res.status(500).json({ success: false, error: 'প্রোডাক্ট আপডেট করা যায়নি' });
    }
});

// ── SELLER: নিজের প্রোডাক্ট ডিলিট করা (ownership check) ──────────────
app.delete('/seller/product/:id', requireSellerToken, async (req, res) => {
    try {
        const email = req.seller.email;
        const productIdNum = Number(req.params.id);
        if (isNaN(productIdNum)) {
            return res.status(400).json({ success: false, error: 'Invalid product id' });
        }

        const deleted = await total_products.findOneAndDelete({ id: productIdNum, seller_email: email });
        if (!deleted) {
            return res.status(404).json({ success: false, error: 'প্রোডাক্ট পাওয়া যায়নি অথবা এটা তোমার নয়' });
        }

        delCache(`prod_${productIdNum}`);
        res.json({ success: true, message: 'প্রোডাক্ট ডিলিট হয়েছে' });
    } catch (err) {
        console.error('❌ seller/product DELETE:', err);
        res.status(500).json({ success: false, error: 'প্রোডাক্ট ডিলিট করা যায়নি' });
    }
});

// ─── Cache Stats ───

app.get('/bd/cache-stats', requireApiKey, (req, res) => res.json(cache.getStats()));

// ════════════════════════════════════════════════════════════
// 🧹 RAM Management
// ════════════════════════════════════════════════════════════

const RAM_THRESHOLD = 50 * 1024 * 1024;
setInterval(() => {
    const freeMem = os.freemem();
    if (freeMem < RAM_THRESHOLD) {
        const freeMB = (freeMem / 1024 / 1024).toFixed(1);
        console.warn(`⚠️ RAM কম! ${freeMB}MB বাকি — Cache clear...`);
        cache.flushAll();
        console.log(`✅ Cache clear | free: ${(os.freemem() / 1024 / 1024).toFixed(1)}MB`);
    }
}, 30 * 1000);

// ════════════════════════════════════════════════════════════
// 🚨 Error Handlers
// ════════════════════════════════════════════════════════════

app.use((req, res) => {
    res.status(404).json({ error: 'Not found', path: req.path });
});

app.use((err, req, res, _next) => {
    console.error('❌ Error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

process.on('uncaughtException', err => console.error('💥 Uncaught:', err));
process.on('unhandledRejection', reason => console.error('💥 Unhandled:', reason));

// ════════════════════════════════════════════════════════════
// 🚀 Start Server
// ════════════════════════════════════════════════════════════

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`✅ CORS enabled for allowed origins`);
    console.log(`✅ JWT-based seller + user auth active`);
    console.log(`✅ Rate limiting active (general + auth)`);
    console.log(`✅ Paperfly dynamic-pickup courier flow active (admin-confirm based)`);
});
