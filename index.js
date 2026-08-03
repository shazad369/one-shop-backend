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
// 🚦 Rate Limiter
// ════════════════════════════════════════════════════════════

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 2000,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip || req.headers['x-forwarded-for'] || 'unknown';
    },
    skip: (req) => req.method === 'OPTIONS'
});

app.use(limiter);
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
    const CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME; // .env: CLOUDINARY_CLOUD_NAME=dittlxqip
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
const userlogindata = mongoose.model('user-login-data', new mongoose.Schema({}, { strict: false }), 'user-login-data');
const cartitem = mongoose.model('cart-item', new mongoose.Schema({}, { strict: false }), 'cartdata');
const locationdata = mongoose.model('location-data', new mongoose.Schema({}, { strict: false }), 'userlocationdata');
const orderdata = mongoose.model('order-data', new mongoose.Schema({}, { strict: false }), 'orderdata');
const total_products = mongoose.model('total-products', new mongoose.Schema({}, { strict: false }), 'total_product');

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

// ════════════════════════════════════════════════════════════
// 📧 Order & Cart Email Helpers
// ════════════════════════════════════════════════════════════

// ⭐ One-click star rating links + "বিস্তারিত রিভিউ" বাটন — শুধু plain <a> ট্যাগ, form/JS লাগে না
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

// প্লেইন-টেক্সট ভার্সন — শুধু HTML পাঠালে spam score বাড়ে
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
            text: text || subject, // plain-text fallback — spam filter এর জন্য জরুরি
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

// ─── Health Check ───
app.get('/', (req, res) => {
    res.json({ status: 'OK', message: 'Server is running' });
});

// ─── Auth Routes ───

app.post('/forgot-password', requireApiKey, async (req, res) => {
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

app.post('/verify-otp', requireApiKey, (req, res) => {
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

app.post('/reset-password', requireApiKey, async (req, res) => {
    try {
        const { email, newPassword } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, error: 'Valid email দাও' });
        }
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ success: false, error: 'Password ৬ character' });
        }
        const updated = await userlogindata.findOneAndUpdate(
            { email },
            { $set: { password: newPassword } },
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
            console.log("⚡ Cache hit:", ck);
            return res.json(hit);
        }

        console.log("🔍 Search:", { q, page, limit, skip, category, sort });

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

app.get('/orders', requireApiKey, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 4;
        const skip = (page - 1) * limit;
        const email = (req.query.email || '').trim();

        const filter = email ? { email } : {};

        const [orders, total] = await Promise.all([
            orderdata.find(filter).sort({ _id: -1 }).skip(skip).limit(limit),
            orderdata.countDocuments(filter),
        ]);

        const result = { orders, total, hasMore: skip + limit < total };
        res.json(result);
    } catch (err) {
        console.error('Orders get error:', err);
        res.status(500).json({ error: 'Orders pawa jayni' });
    }
});

// ─── Order Routes ───

app.post('/orders', requireApiKey, async (req, res) => {
    try {
        const newData = new orderdata(req.body);
        await newData.save();
        delCache('all_orders');
        res.status(201).json(newData);

        // 📧 Order confirmation email — fire and forget, doesn't block the response
        const { email, title, name, image, price, quantity, size, category, address, productId } = req.body;
        const emailParams = {
            heading: 'Order Confirmed!',
            subheading: `প্রিয় ${name || 'customer'}, আপনার অর্ডারটি সফলভাবে গ্রহণ করা হয়েছে।`,
            id: productId,
            title,
            image: toCloudinaryUrl(image),
            price, quantity, size, category, address,
            email,
            showReview: true, // 👈 order confirm email-এই review/rating link দেখাও
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
        const cacheKeyName = `orders_page_${page}_limit_${limit}`;
        const hit = getCache(cacheKeyName);
        if (hit) return res.json(hit);
        const [orders, total] = await Promise.all([
            orderdata.find({}).skip(skip).limit(limit),
            orderdata.countDocuments(),
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

app.post('/logindata', requireApiKey, async (req, res) => {
    try {
        const { email, name, picture, googleId } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, error: 'Valid email দাও' });
        }
        const existing = await userlogindata.findOne({ email });
        if (existing) {
            return res.status(200).json({ success: true, message: 'User already exists', data: existing, isNew: false });
        }
        const newData = new userlogindata({ email, name, picture, googleId });
        await newData.save();
        res.status(201).json({ success: true, message: 'Saved', data: newData, isNew: true });
    } catch (err) {
        console.error('Login data save error:', err);
        res.status(500).json({ success: false, error: 'Save error' });
    }
});

app.post('/loginnewdata', requireApiKey, async (req, res) => {
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
            return res.status(200).json({ success: true, message: 'User already exists', data: existing, isNew: false });
        }
        const newData = new userlogindata({ email, password });
        await newData.save();
        res.status(201).json({ success: true, message: 'Saved', data: newData, isNew: true });
    } catch (err) {
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

app.post('/relogin', requireApiKey, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ success: false, error: 'Valid email দাও' });
        }
        const query = password ? { email, password } : { email };
        const user = await userlogindata.findOne(query);
        if (user) {
            res.json({ success: true, user });
        } else {
            res.json({ success: false });
        }
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
        await cartitem.deleteOne({ productId });
        const newCartItem = new cartitem(req.body);
        await newCartItem.save();
        delCache(`cart_${email}`);
        res.status(201).json(newCartItem);

        // 📧 Add-to-cart email — fire and forget, doesn't block the response
        const { title, image, price, quantity, size, category } = req.body;
        const emailParams = {
            heading: 'Cart-এ যোগ হয়েছে',
            subheading: 'আপনার পছন্দের প্রোডাক্টটি cart-এ যোগ হয়েছে।',
            id: productId,
            title,
            image: toCloudinaryUrl(image),
            price, quantity, size, category,
            email,
            showReview: false, // 👈 cart এ যোগ করার সময় review চাওয়া উচিত না, product হাতে পাওয়ার আগে
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

// ⭐ Email থেকে ক্লিক করে one-click rating (no form, no JS — plain link + GET)
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
    console.log(`✅ CORS enabled for all origins`);
    console.log(`✅ Rate limiting active`);
    console.log(`✅ Routes: /bd/shopdata, /bd/orders, etc.`);
});