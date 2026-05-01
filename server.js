/* ═══════════════════════════════════════════════════════════════
   Muchhad Backend · Express Server
   ─────────────────────────────────────────────────────────────
   STEP 1 — Security & Data Integrity
   Changes vs previous:
     🔒 Idempotency keys on order creation
     🔒 Atomic order creation via Postgres function (transactional)
     🔒 Coupon usage moved from create → webhook (only paid counts)
     🔒 Atomic coupon redemption via redeem_coupon() RPC
     🔒 Webhook deduplication via webhook_events table
     🔒 Status transition guards (no failed → paid regression)
     🔒 Rate limiting on all sensitive endpoints
     🔒 CORS hardened (HTTPS only in production)
═══════════════════════════════════════════════════════════════ */

require('dotenv').config({ override: true });
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const crypto    = require('crypto');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const shiprocket = require('./shiprocket');
const email      = require('./email');



const app  = express();
const PORT = process.env.PORT || 3001;

const SUPPORT_EMAIL = 'support@muchhadeats.in';
const VALID_SIZES   = ['200g', '350g'];
const DEFAULT_SIZE  = '200g';
const IS_PROD       = process.env.NODE_ENV === 'production';

/* ── Supabase (service role — bypasses RLS) ── */
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);


shiprocket.init(supabase);
shiprocket.startAutoSync();

/* ── Cashfree config ── */
const CF = {
  appId:     process.env.CASHFREE_APP_ID,
  secretKey: process.env.CASHFREE_SECRET_KEY,
  baseUrl:   process.env.CASHFREE_BASE_URL   || 'https://sandbox.cashfree.com/pg',
  version:   process.env.CASHFREE_API_VERSION || '2023-08-01'
};

const API_BASE_URL = process.env.API_BASE_URL || 'https://api.muchhadeats.in';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://muchhadeats.in';

/* ═══════════════════════════════════════════════════════════════
   MIDDLEWARE
═══════════════════════════════════════════════════════════════ */
app.use(helmet());

// 🔒 STEP 1: HTTPS-only CORS in production. http:// origins removed.
const allowedOrigins = IS_PROD
  ? ['https://muchhadeats.in', 'https://www.muchhadeats.in']
  : ['https://muchhadeats.in', 'https://www.muchhadeats.in', 'http://localhost:3000', 'http://127.0.0.1:5500', 'http://127.0.0.1:5501'];

app.use(cors({
  origin: (origin, cb) => {
    // Allow no-origin requests (mobile apps, server-to-server, Postman)
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('CORS: origin not allowed'));
  },
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true
}));

// Trust the first proxy (Hostinger / Cloudflare) so req.ip is correct for rate limiting
app.set('trust proxy', 1);

app.use(express.json({
  limit: '10mb',  // increased from 100KB default to allow base64 image uploads (~7MB max image becomes ~9MB base64)
  verify: (req, res, buf) => {
    // Save raw bytes so the Cashfree webhook handler can verify HMAC
    req.rawBody = buf.toString('utf8');
  }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

/* ═══════════════════════════════════════════════════════════════
   🔒 STEP 1: RATE LIMITERS
═══════════════════════════════════════════════════════════════ */
const orderCreateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 min
  max: 8,                   // 8 order attempts per IP per 10 min
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many order attempts. Please wait a few minutes.' }
});

const couponLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,  // 5 min
  max: 15,                  // 15 coupon attempts per IP per 5 min
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many coupon attempts. Please wait a few minutes.' }
});

const verifyLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,  // 1 min
  max: 30,                  // 30 polls per IP per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many verification attempts.' }
});




/* ═══════════════════════════════════════════════════════════════
   🔒 STEP 3.3: JWT AUTH MIDDLEWARE
   ─────────────────────────────────────────────────────────────
   Extracts the Supabase JWT from the Authorization header,
   verifies it with Supabase, and attaches req.authUser.
   
   Use `requireAuth` for endpoints that must have a logged-in user.
═══════════════════════════════════════════════════════════════ */
async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
      return res.status(401).json({ error: 'Authentication required. Please sign in.' });
    }

    // Supabase verifies the JWT signature + expiry
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data?.user) {
      console.warn('[Auth] Invalid token:', error?.message);
      return res.status(401).json({ error: 'Session expired. Please sign in again.' });
    }

    // Attach user to request for handlers to use
    req.authUser = data.user;
    next();
  } catch (err) {
    console.error('[Auth middleware] Error:', err);
    return res.status(500).json({ error: 'Auth check failed.' });
  }
}

/* ═══════════════════════════════════════════════════════════════
   🔒 ADMIN AUTH MIDDLEWARE
   ─────────────────────────────────────────────────────────────
   1. Validates the JWT (same as requireAuth)
   2. Checks the user's email is in the ADMIN_EMAILS env var allowlist
   
   Env config required:
     ADMIN_EMAILS=vikash@muchhad.in,deepanshu@muchhad.in
   
   The comma-separated list is case-insensitive and whitespace-tolerant.
   Any email NOT in the list gets a 403 — even if their JWT is valid.
═══════════════════════════════════════════════════════════════ */
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
  .split(',')
  .map(e => e.trim().toLowerCase())
  .filter(Boolean);

if (ADMIN_EMAILS.length === 0 && IS_PROD) {
  console.warn('[Admin] ⚠️  ADMIN_EMAILS env var is empty in production. Admin dashboard will be inaccessible.');
} else if (ADMIN_EMAILS.length > 0) {
  console.log(`[Admin] ${ADMIN_EMAILS.length} admin email(s) configured.`);
}

function isAdminEmail(email) {
  if (!email) return false;
  return ADMIN_EMAILS.includes(email.trim().toLowerCase());
}

async function requireAdmin(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data?.user) {
      return res.status(401).json({ error: 'Session expired. Please sign in again.' });
    }

    if (!isAdminEmail(data.user.email)) {
      console.warn(`[Admin] Access denied for ${data.user.email}`);
      return res.status(403).json({ error: 'Admin access required.' });
    }

    req.authUser = data.user;
    next();
  } catch (err) {
    console.error('[requireAdmin] Error:', err);
    return res.status(500).json({ error: 'Auth check failed.' });
  }
}




/* ═══════════════════════════════════════════════════════════════
   PRICE HELPERS
═══════════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════════
   PRICE HELPERS
   Chat C3: variant-aware. If a product has a `product_variants` array
   (loaded via JOIN) and we know the variant_id or matching size label,
   use that variant's price. Falls back to legacy price/price_large.
═══════════════════════════════════════════════════════════════ */

/* Find a variant inside a product. variantOrSize may be either a UUID or a label like '200g' */
function findVariant(product, variantOrSize) {
  if (!product || !Array.isArray(product.product_variants)) return null;
  return product.product_variants.find(v =>
    v.id === variantOrSize || v.label === variantOrSize
  ) || null;
}

function getMRP(product, size, variantId) {
  // Prefer variant lookup if we have one
  const v = (variantId && findVariant(product, variantId)) || findVariant(product, size);
  if (v) {
    return Number(v.mrp != null ? v.mrp : v.price);
  }
  // Legacy fallback
  if (size === '350g' && product.price_large) return Number(product.price_large);
  return Number(product.price);
}

function getUnitPrice(product, size, variantId) {
  // If we have a variant, use its price directly (already the final selling price for that variant)
  const v = (variantId && findVariant(product, variantId)) || findVariant(product, size);
  if (v) {
    const variantPrice = Number(v.price);
    const disc = Number(product.discount_percent || 0);
    // The variant.price IS the mrp; discount applies on top.
    if (disc > 0 && disc < 100) {
      return Math.round(variantPrice * (1 - disc / 100));
    }
    return variantPrice;
  }
  // Legacy path: use the old getMRP
  const mrp = getMRP(product, size);
  const disc = Number(product.discount_percent || 0);
  if (disc > 0 && disc < 100) {
    return Math.round(mrp * (1 - disc / 100));
  }
  return mrp;
}

/* ═══════════════════════════════════════════════════════════════
   ROUTES
═══════════════════════════════════════════════════════════════ */

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'muchhad-api', timestamp: new Date().toISOString() });
});

// 🔧 TEMPORARY DEBUG ENDPOINT — remove after webhook is fixed
// 🔧 TEMPORARY — verify Shiprocket env vars are what we expect

/* ──────────────────────────────────────────────────────────────
   POST /api/orders/create
   ──────────────────────────────────────────────────────────────
   Body: {
     idempotency_key: uuid,            // 🔒 NEW
     customer: { name, phone, address, city, state, pincode, email? },
     items: [{ product_id, quantity, size, options }],
     coupon_code?: string
   }
────────────────────────────────────────────────────────────── */
app.post('/api/orders/create', orderCreateLimiter, requireAuth, async (req, res) => {
  try {
    const { idempotency_key, customer, items, coupon_code } = req.body;

    /* ── Validate input ── */
    if (!idempotency_key || typeof idempotency_key !== 'string' || idempotency_key.length < 16) {
      return res.status(400).json({ error: 'Missing or invalid idempotency_key.' });
    }
    if (!customer?.name || !customer?.phone || !customer?.address) {
      return res.status(400).json({ error: 'Missing required customer fields.' });
    }
    if (!/^\d{10}$/.test(customer.phone)) {
      return res.status(400).json({ error: 'Invalid phone number.' });
    }
    if (!items?.length) {
      return res.status(400).json({ error: 'Cart is empty.' });
    }

    const customerEmail = customer.email?.trim() || null; // 🔒 NULL if blank, no fake fallback

    /* ── Fetch product data from DB (with their variants for pricing/validation) ── */
    const productIds = items.map(i => i.product_id);
    const { data: products, error: prodErr } = await supabase
      .from('products')
      .select('id, name, slug, price, price_large, discount_percent, stock_status, is_active, is_combo, archived_at, product_variants(id, label, size_value, size_unit, price, mrp, is_active, archived_at)')
      .in('id', productIds);

    if (prodErr) throw prodErr;

    const productMap = {};
    products.forEach(p => {
      // Filter out inactive/archived variants up front
      if (Array.isArray(p.product_variants)) {
        p.product_variants = p.product_variants.filter(v => v.is_active && !v.archived_at);
      }
      productMap[p.id] = p;
    });

    /* ── Validate each item ── */
    for (const item of items) {
      const prod = productMap[item.product_id];
      if (!prod) return res.status(400).json({ error: `Product #${item.product_id} not found.` });
      if (!prod.is_active) return res.status(400).json({ error: `${prod.name} is currently unavailable.` });
      if (prod.archived_at) return res.status(400).json({ error: `${prod.name} is no longer available.` });
      if (prod.stock_status === 'out_of_stock') return res.status(400).json({ error: `${prod.name} is out of stock.` });

      const size = item.size || DEFAULT_SIZE;
      const variantId = item.variant_id || null;

      // Variant-aware validation:
      // - If variant_id is given, it must exist and belong to this product (active+non-archived)
      // - Else, if product has variants, the size label must match one of them
      // - Else (legacy product without variants), allow VALID_SIZES
      const hasVariants = Array.isArray(prod.product_variants) && prod.product_variants.length > 0;

      if (variantId) {
        const matchedVariant = prod.product_variants.find(v => v.id === variantId);
        if (!matchedVariant) {
          return res.status(400).json({ error: `Invalid or unavailable variant for ${prod.name}.` });
        }
      } else if (hasVariants) {
        const matchedBySize = prod.product_variants.find(v => v.label === size);
        if (!matchedBySize) {
          return res.status(400).json({ error: `Size "${size}" is not available for ${prod.name}.` });
        }
        // Backfill variant_id from size match — keeps order_items linked even for old clients
        item.variant_id = matchedBySize.id;
      } else {
        // Legacy product (no variants) — fall back to old hardcoded check
        if (!VALID_SIZES.includes(size)) {
          return res.status(400).json({ error: `Invalid size "${size}" for ${prod.name}.` });
        }
      }

      if (!Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 50) {
        return res.status(400).json({ error: `Invalid quantity for ${prod.name}.` });
      }

      if (prod.slug === 'combo-pick-4') {
        const opts = item.options || item.item_options || {};
        const selections = opts.selected_flavors || [];
        if (!Array.isArray(selections) || selections.length !== 4) {
          return res.status(400).json({ error: 'Pick Any 4 combo requires exactly 4 flavour selections.' });
        }
        const validSlugs = new Set(
          (await supabase.from('products').select('slug').eq('is_combo', false).eq('is_active', true))
            .data?.map(r => r.slug) || []
        );
        for (const slug of selections) {
          if (!validSlugs.has(slug)) {
            return res.status(400).json({ error: `Invalid flavour selection: ${slug}` });
          }
        }
      }
    }

    /* ── Calculate totals server-side ── */
    let subtotal = 0;
    const orderItems = items.map(item => {
      const prod = productMap[item.product_id];
      const size = item.size || DEFAULT_SIZE;
      const variantId = item.variant_id || null;
      const unitPrice = getUnitPrice(prod, size, variantId);
      const lineTotal = unitPrice * item.quantity;
      subtotal += lineTotal;
      const oi = {
        product_id:   prod.id,
        product_name: prod.name,
        quantity:     item.quantity,
        unit_price:   unitPrice,
        line_total:   lineTotal,
        size:         size,
        item_options: item.options || item.item_options || {}
      };
      if (variantId) oi.variant_id = variantId;
      return oi;
    });

    /* ── Validate coupon (informational only — actual redemption happens on payment success) ── */
    // 🔒 STEP 1: We compute the discount here so the customer sees the correct total,
    // but we do NOT mark the coupon as used. That happens only on confirmed payment.
    let discount = 0;
    let validatedCouponCode = null;
    if (coupon_code) {
      const { data: coupon } = await supabase
        .from('coupons')
        .select('*')
        .eq('code', coupon_code.toUpperCase())
        .eq('is_active', true)
        .maybeSingle();

      if (coupon) {
        const now = new Date();
        const notExpired = !coupon.expires_at || new Date(coupon.expires_at) > now;
        // Read actual usage from coupon_redemptions, not the denormalized counter
        const { count: usedCount } = await supabase
          .from('coupon_redemptions')
          .select('id', { count: 'exact', head: true })
          .eq('coupon_id', coupon.id);
        const notMaxed = !coupon.max_uses || (usedCount || 0) < coupon.max_uses;
        const meetsMin = subtotal >= (coupon.min_order_value || 0);

        if (notExpired && notMaxed && meetsMin) {
          validatedCouponCode = coupon.code;
          discount = coupon.discount_type === 'percentage'
            ? Math.round(subtotal * coupon.discount_value / 100)
            : Number(coupon.discount_value);
          discount = Math.min(discount, subtotal);
        }
      }
    }

    let freeThreshold = 499;
let shippingFeeAmount = 49;
try {
  const { data: shipSettings } = await supabase
    .from('settings')
    .select('key, value')
    .in('key', ['free_shipping_threshold', 'shipping_fee']);
  if (shipSettings) {
    shipSettings.forEach(row => {
      if (row.key === 'free_shipping_threshold') freeThreshold = Number(row.value) || 499;
      if (row.key === 'shipping_fee') shippingFeeAmount = Number(row.value) || 49;
    });
  }
} catch (e) { /* use defaults */ }

const shippingFee = subtotal >= freeThreshold ? 0 : shippingFeeAmount;
    const totalAmount = subtotal - discount + shippingFee;

    /* ── 🔒 STEP 1: Atomic order creation via RPC ── */
    /* ── 🔒 STEP 1 + 3.3: Atomic order creation via RPC ── */
    const { data: rpcResult, error: rpcErr } = await supabase.rpc('create_order_transactional_v2', {
      p_idempotency_key: idempotency_key,
      p_auth_user_id: req.authUser.id,     // 🆕 Step 3.3: link order to auth user
      p_customer: {
        name:    customer.name,
        email:   customerEmail,
        phone:   customer.phone,
        address: customer.address,
        city:    customer.city || '',
        state:   customer.state || '',
        pincode: customer.pincode || ''
      },
      p_order: {
        subtotal,
        shipping_fee:    shippingFee,
        discount_amount: discount,
        total_amount:    totalAmount,
        coupon_code:     validatedCouponCode
      },
      p_items: orderItems
    });

    if (rpcErr) {
      console.error('[create_order_transactional_v2] failed:', rpcErr);
      throw rpcErr;
    }

    const orderId      = rpcResult.order_id;
    const orderNumber  = rpcResult.order_number;
    const isReplay     = rpcResult.idempotent_replay;

    // 🔒 If this was an idempotent replay, fetch the existing Cashfree session
    if (isReplay) {
      const { data: existingOrder } = await supabase
        .from('orders')
        .select('cashfree_order_id')
        .eq('id', orderId)
        .single();

      // Re-fetch the payment session from Cashfree
      const cfRes = await fetch(`${CF.baseUrl}/orders/${orderId}`, {
        headers: {
          'x-client-id':     CF.appId,
          'x-client-secret': CF.secretKey,
          'x-api-version':   CF.version
        }
      });
      const cfData = await cfRes.json();

      return res.json({
        success:             true,
        order_id:            orderId,
        order_number:        orderNumber,
        total_amount:        rpcResult.total_amount,
        cashfree_session_id: cfData.payment_session_id,
        idempotent_replay:   true
      });
    }

    /* ── Create Cashfree payment session ── */
    const cfOrderPayload = {
      order_id:       orderId,
      order_amount:   totalAmount,
      order_currency: 'INR',
      customer_details: {
        customer_id:    rpcResult.customer_id || orderId,
        customer_name:  customer.name,
        customer_email: customerEmail || SUPPORT_EMAIL, // Cashfree requires an email
        customer_phone: customer.phone
      },
      order_meta: {
        return_url: `${FRONTEND_URL}/order-status?order_id=${orderId}`,
        notify_url: `${API_BASE_URL.replace(/\/$/, '')}/api/payments/webhook`
      }
    };

    const cfResponse = await fetch(`${CF.baseUrl}/orders`, {
      method: 'POST',
      headers: {
        'Content-Type':    'application/json',
        'x-client-id':     CF.appId,
        'x-client-secret': CF.secretKey,
        'x-api-version':   CF.version
      },
      body: JSON.stringify(cfOrderPayload)
    });

    const cfData = await cfResponse.json();

    if (!cfResponse.ok) {
      console.error('[Cashfree] Order creation failed:', cfData);
      // Order is saved in DB but Cashfree failed — customer can retry
      return res.status(502).json({
        error: 'Payment gateway error. Your order is saved — please try again.',
        order_id: orderId,
        order_number: orderNumber
      });
    }

    await supabase.from('orders')
      .update({ cashfree_order_id: cfData.cf_order_id || cfData.order_id })
      .eq('id', orderId);

    res.json({
      success:             true,
      order_id:            orderId,
      order_number:        orderNumber,
      total_amount:        totalAmount,
      cashfree_session_id: cfData.payment_session_id,
      cashfree_order_id:   cfData.cf_order_id || cfData.order_id,
      payment_link:        cfData.payment_link || null
    });

  } catch (err) {
    console.error('[/api/orders/create] Error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});


/* ──────────────────────────────────────────────────────────────
   POST /api/payments/webhook  (Cashfree → us)
────────────────────────────────────────────────────────────── */
app.post('/api/payments/webhook', async (req, res) => {
  try {
    const signature = req.headers['x-webhook-signature'];
    const ts        = req.headers['x-webhook-timestamp'];
    const rawBody   = req.rawBody;

    if (!signature || !ts || !rawBody) {
      console.warn('[Webhook] Missing signature/timestamp/body — rejecting.');
      return res.status(400).json({ error: 'Missing signature data' });
    }

    // Replay-attack protection: reject anything older than 5 min or future-dated
    // Reject webhooks older than 5 minutes (replay-attack protection)
    // Cashfree sends timestamp in MILLISECONDS (13 digits), not seconds.
    // We auto-detect: if length >= 13, treat as ms; else treat as seconds.
    const tsNum = Number(ts);
    const tsSec = String(ts).length >= 13 ? tsNum / 1000 : tsNum;
    const nowSec = Date.now() / 1000;
    const ageSeconds = nowSec - tsSec;
    console.log(`[Webhook] Timestamp check: ts=${ts}, age=${ageSeconds.toFixed(1)}s`);
    
    if (Number.isNaN(ageSeconds) || ageSeconds > 300 || ageSeconds < -60) {
      console.warn('[Webhook] Stale or future-dated timestamp — rejecting.');
      return res.status(401).json({ error: 'Stale webhook' });
    }







    if (!CF.secretKey) {
      console.error('[Webhook] CASHFREE_SECRET_KEY not set in environment!');
      return res.status(500).json({ error: 'Server misconfigured' });
    }
    

    // Try BOTH signature formats — Cashfree's API version 2023-08-01 uses 
    // (timestamp + rawBody), while older 2021-09-21 uses just rawBody.
    // We accept either to handle dashboard misconfigurations.
    const sigNew = crypto
      .createHmac('sha256', CF.secretKey)
      .update(ts + rawBody)
      .digest('base64');
    
    const sigOld = crypto
      .createHmac('sha256', CF.secretKey)
      .update(rawBody)
      .digest('base64');
    
    const sigBuf = Buffer.from(signature, 'base64');
    const newBuf = Buffer.from(sigNew, 'base64');
    const oldBuf = Buffer.from(sigOld, 'base64');
    
    const matchesNew = sigBuf.length === newBuf.length && crypto.timingSafeEqual(sigBuf, newBuf);
    const matchesOld = sigBuf.length === oldBuf.length && crypto.timingSafeEqual(sigBuf, oldBuf);
    
    if (!matchesNew && !matchesOld) {
      console.warn('[Webhook] Invalid signature — rejecting.');
      console.warn('[Webhook] Expected (new format):', sigNew);
      console.warn('[Webhook] Expected (old format):', sigOld);
      console.warn('[Webhook] Received:             ', signature);
      return res.status(401).json({ error: 'Invalid signature' });
    }
    
    console.log(`[Webhook] Signature verified (${matchesNew ? '2023-08-01' : '2021-09-21'} format)`);

    const { data, type } = req.body;
    if (!data?.order?.order_id) {
      return res.status(400).json({ error: 'Missing order ID in webhook' });
    }

    const orderId       = data.order.order_id;
    const paymentStatus = data.payment?.payment_status;
    const cfPaymentId   = data.payment?.cf_payment_id;

    // 🔒 STEP 1: Build a unique event ID for deduplication.
    // Cashfree's payload doesn't always have a top-level event_id, so we
    // synthesize one from order_id + payment_status + cf_payment_id.
    const eventId = `${orderId}:${paymentStatus}:${cfPaymentId || 'none'}`;

    // 🔒 STEP 1: Dedupe — try to insert into webhook_events first.
    // If it already exists, this is a retry and we ack without reprocessing.
    const { error: dedupeErr } = await supabase
      .from('webhook_events')
      .insert({
        source: 'cashfree',
        event_id: eventId,
        event_type: type || 'PAYMENT_WEBHOOK',
        order_id: orderId,
        payload: req.body
      });

    if (dedupeErr) {
      // 23505 = unique_violation = duplicate webhook, already processed
      if (dedupeErr.code === '23505') {
        console.log(`[Webhook] Duplicate event ${eventId} — already processed, acking.`);
        return res.json({ status: 'ok', deduped: true });
      }
      console.error('[Webhook] Dedupe insert failed:', dedupeErr);
      // Keep going — we'd rather process twice than miss a payment
    }

    let dbPaymentStatus = 'pending';
    let dbOrderStatus   = 'pending';

    if (paymentStatus === 'SUCCESS') {
      dbPaymentStatus = 'paid';
      dbOrderStatus   = 'confirmed';
    } else if (['FAILED', 'CANCELLED', 'USER_DROPPED'].includes(paymentStatus)) {
      dbPaymentStatus = 'failed';
      dbOrderStatus   = 'cancelled';
    }

    // 🔒 STEP 1: Use the guarded RPC so failed → paid regression is impossible
    const { data: updated, error: updateErr } = await supabase.rpc('update_order_payment_status', {
      p_order_id:         orderId,
      p_new_status:       dbPaymentStatus,
      p_new_order_status: dbOrderStatus,
      p_cf_payment_id:    cfPaymentId?.toString() || null
    });

    if (updateErr) {
      console.error('[Webhook] Status update failed:', updateErr);
      return res.status(500).json({ error: 'DB update failed' });
    }

    // 🔒 STEP 1: On payment success, redeem the coupon (atomic, transactional).
    if (dbPaymentStatus === 'paid') {
      const { data: order } = await supabase
        .from('orders')
        .select('coupon_code, discount_amount, customer_phone')
        .eq('id', orderId)
        .single();

      if (order?.coupon_code && order.discount_amount > 0) {
        const { error: redeemErr } = await supabase.rpc('redeem_coupon', {
          p_coupon_code:     order.coupon_code,
          p_order_id:        orderId,
          p_customer_phone:  order.customer_phone,
          p_discount_amount: order.discount_amount
        });
        if (redeemErr) {
          // Coupon redemption failure is not fatal — log and continue.
          // Most likely cause: this exact (coupon, order) pair was already redeemed by a retry.
          console.warn(`[Webhook] Coupon redemption skipped for order ${orderId}:`, redeemErr.message);
        }
      }

      // 🚚 STEP 10: Push to Shiprocket (respects settings.shiprocket_auto_push)
      try {
        const { data: setting } = await supabase
          .from('settings')
          .select('value')
          .eq('key', 'shiprocket_auto_push')
          .maybeSingle();
        
        const autoPush = setting?.value !== false;  // default true
        
        if (autoPush) {
          // Fire-and-forget so webhook response isn't delayed by Shiprocket API
          shiprocket.pushOrderToShiprocket(orderId).catch(err => {
            console.error(`[Webhook] Shiprocket push failed for ${orderId}:`, err.message);
          });
        } else {
          console.log(`[Webhook] Shiprocket auto-push disabled. Order ${orderId} marked for manual push.`);
          await supabase.from('orders').update({ needs_shiprocket_push: true }).eq('id', orderId);
        }
      } catch (spErr) {
        console.error(`[Webhook] Shiprocket wiring error:`, spErr);
      }

      // Send order confirmation email — fire-and-forget, idempotent
      email.sendOrderConfirmation({ supabase, orderId })
        .then(r => {
          if (r.sent) console.log(`[Webhook] Email sent for order ${orderId}`);
          else        console.log(`[Webhook] Email skipped for ${orderId}: ${r.reason}`);
        })
        .catch(err => console.error(`[Webhook] Email error for ${orderId}:`, err.message));
    }

    console.log(`[Webhook] Order ${orderId} → ${dbPaymentStatus}`);
    res.json({ status: 'ok' });

  } catch (err) {
    console.error('[Webhook] Error:', err);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});


/* ──────────────────────────────────────────────────────────────
   GET /api/orders/:orderId/status
────────────────────────────────────────────────────────────── */
app.get('/api/orders/:orderId/status', async (req, res) => {
  try {
    const { orderId } = req.params;

    const { data: order, error } = await supabase
      .from('orders')
      .select('id, order_number, customer_name, customer_phone, total_amount, payment_status, order_status, tracking_number, tracking_url, created_at')
      .eq('id', orderId)
      .single();

    if (error || !order) {
      return res.status(404).json({ error: 'Order not found.' });
    }

    const { data: items } = await supabase
      .from('order_items')
      .select('product_name, quantity, unit_price, line_total, size, item_options')
      .eq('order_id', orderId);

    res.json({ order, items: items || [] });

  } catch (err) {
    console.error('[/api/orders/status] Error:', err);
    res.status(500).json({ error: 'Failed to fetch order.' });
  }
});


/* ──────────────────────────────────────────────────────────────
   POST /api/payments/verify
────────────────────────────────────────────────────────────── */
app.post('/api/payments/verify', verifyLimiter, async (req, res) => {
  try {
    const { order_id } = req.body;
    if (!order_id) return res.status(400).json({ error: 'Missing order_id' });

    // 🔒 STEP 1: Check our DB first. If the webhook already finalized the order,
    // we trust that and don't risk a status regression by calling Cashfree.
    const { data: existing } = await supabase
      .from('orders')
      .select('payment_status')
      .eq('id', order_id)
      .single();

    if (existing?.payment_status === 'paid') {
      return res.json({ status: 'paid' });
    }
    if (existing?.payment_status === 'failed') {
      return res.json({ status: 'failed' });
    }

    // Order is still pending — ask Cashfree for the latest
    const cfRes = await fetch(`${CF.baseUrl}/orders/${order_id}/payments`, {
      headers: {
        'x-client-id':     CF.appId,
        'x-client-secret': CF.secretKey,
        'x-api-version':   CF.version
      }
    });

    const payments = await cfRes.json();

    if (!cfRes.ok) {
      return res.status(502).json({ error: 'Could not verify payment with Cashfree.' });
    }

    const successfulPayment = Array.isArray(payments)
      ? payments.find(p => p.payment_status === 'SUCCESS')
      : null;

    if (successfulPayment) {
      // 🔒 Use the guarded RPC instead of a direct UPDATE
      await supabase.rpc('update_order_payment_status', {
        p_order_id:         order_id,
        p_new_status:       'paid',
        p_new_order_status: 'confirmed',
        p_cf_payment_id:    successfulPayment.cf_payment_id?.toString() || null
      });

      // Send confirmation email (idempotent — won't double-send if webhook already triggered it)
      email.sendOrderConfirmation({ supabase, orderId: order_id })
        .then(r => {
          if (r.sent) console.log(`[Verify] Email sent for order ${order_id}`);
          else        console.log(`[Verify] Email skipped for ${order_id}: ${r.reason}`);
        })
        .catch(err => console.error(`[Verify] Email error for ${order_id}:`, err.message));

      return res.json({ status: 'paid', payment: successfulPayment });
    }

    res.json({ status: 'pending', payments });

  } catch (err) {
    console.error('[/api/payments/verify] Error:', err);
    res.status(500).json({ error: 'Verification failed.' });
  }
});


/* ──────────────────────────────────────────────────────────────
   POST /api/coupons/validate
────────────────────────────────────────────────────────────── */
app.post('/api/coupons/validate', couponLimiter, async (req, res) => {
  try {
    const { code, subtotal } = req.body;
    if (!code) return res.status(400).json({ error: 'No coupon code provided.' });
    if (typeof subtotal !== 'number' || subtotal < 0) {
      return res.status(400).json({ error: 'Invalid subtotal.' });
    }

    const { data: coupon } = await supabase
      .from('coupons')
      .select('*')
      .eq('code', code.toUpperCase())
      .eq('is_active', true)
      .maybeSingle();

    if (!coupon) return res.json({ valid: false, message: 'Invalid coupon code.' });

    const now = new Date();
    if (coupon.expires_at && new Date(coupon.expires_at) < now) {
      return res.json({ valid: false, message: 'This coupon has expired.' });
    }

    // 🔒 STEP 1: Read actual usage from coupon_redemptions
    const { count: usedCount } = await supabase
      .from('coupon_redemptions')
      .select('id', { count: 'exact', head: true })
      .eq('coupon_id', coupon.id);

    if (coupon.max_uses && (usedCount || 0) >= coupon.max_uses) {
      return res.json({ valid: false, message: 'This coupon has been fully redeemed.' });
    }

    if (subtotal < (coupon.min_order_value || 0)) {
      const needed = (coupon.min_order_value || 0) - subtotal;
      return res.json({
        valid: false,
        message: `Add ₹${needed} more to use this coupon (min order ₹${coupon.min_order_value}).`
      });
    }

    const discount = coupon.discount_type === 'percentage'
      ? Math.round(subtotal * coupon.discount_value / 100)
      : Number(coupon.discount_value);

    res.json({
      valid: true,
      discount_type:   coupon.discount_type,
      discount_value:  coupon.discount_value,
      discount_amount: Math.min(discount, subtotal),
      message: coupon.discount_type === 'percentage'
        ? `${coupon.discount_value}% off applied!`
        : `₹${coupon.discount_value} off applied!`
    });

  } catch (err) {
    console.error('[/api/coupons/validate] Error:', err);
    res.status(500).json({ error: 'Could not validate coupon.' });
  }
});


/* ──────────────────────────────────────────────────────────────
   ANALYTICS — removed April 2026.
   The old /api/analytics/event endpoint wrote to an analytics_events
   table that was never created. Frontend DB.trackEvent() is a no-op.
   Re-introduce via PostHog / Plausible post-launch.
────────────────────────────────────────────────────────────── */


/* ──────────────────────────────────────────────────────────────
   🚚 STEP 10: Shiprocket endpoints
────────────────────────────────────────────────────────────── */

// Pincode serviceability check (called from checkout)
app.get('/api/shipping/serviceability/:pincode', async (req, res) => {
  try {
    const { pincode } = req.params;
    const result = await shiprocket.checkPincodeServiceability(pincode);
    res.json(result);
  } catch (err) {
    console.error('[serviceability] Error:', err);
    res.status(500).json({ serviceable: false, error: err.message });
  }
});

// Manual retry for failed Shiprocket pushes (admin only)
app.post('/api/admin/shiprocket/push/:orderId', requireAdmin, async (req, res) => {
  try {
    const result = await shiprocket.pushOrderToShiprocket(req.params.orderId);
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});


// Sync AWB/courier from Shiprocket after manual assignment
app.get('/api/admin/shiprocket/sync/:orderNumber', async (req, res) => {
  const key = req.query.key;
  if (key !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: 'Invalid admin key' });
  }
  try {
    const result = await shiprocket.syncOrderFromShiprocket(req.params.orderNumber);
    res.json({ success: true, ...result });
  } catch (err) {
    console.error('[Shiprocket Sync] Error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});


// Shiprocket webhook (delivery status updates from them → us)
// Shiprocket webhook (delivery status updates from them → us)
app.post('/api/delivery/webhook', async (req, res) => {
  try {
    // 🔒 Verify the pre-shared token Shiprocket sends back in the header.
    // Shiprocket sends whatever token you set in their dashboard as `x-api-key`.
    const expectedToken = process.env.SHIPROCKET_WEBHOOK_TOKEN;
    const receivedToken = req.headers['x-api-key'] || req.headers['x-shiprocket-token'];

    if (!expectedToken) {
      console.error('[Shiprocket Webhook] SHIPROCKET_WEBHOOK_TOKEN env var not set — rejecting all webhooks.');
      return res.status(500).json({ error: 'Webhook auth not configured on server' });
    }

    if (!receivedToken || receivedToken !== expectedToken) {
      console.warn(`[Shiprocket Webhook] Rejected: bad or missing token. Got header: ${receivedToken ? 'present-but-wrong' : 'missing'}`);
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const payload = req.body || {};
    const awb = payload.awb || payload.awb_code;
    const currentStatus = payload.current_status || payload.status;
    const srOrderId = payload.order_id;
    
    console.log(`[Shiprocket Webhook] Received (verified): AWB=${awb}, status=${currentStatus}, srOrderId=${srOrderId}`);

    if (!awb && !srOrderId) {
      return res.status(400).json({ error: 'Missing AWB and order_id' });
    }

    // Try to find order — first by AWB, then by shiprocket_order_id
    let order = null;

    if (awb) {
      const { data } = await supabase
        .from('orders')
        .select('id, order_status, order_number, awb_code')
        .eq('awb_code', awb)
        .maybeSingle();
      order = data;
    }

    if (!order && srOrderId) {
      const { data } = await supabase
        .from('orders')
        .select('id, order_status, order_number, awb_code')
        .eq('shiprocket_order_id', String(srOrderId))
        .maybeSingle();
      order = data;
    }

    if (!order) {
      console.warn(`[Shiprocket Webhook] No matching order for AWB=${awb}, srOrderId=${srOrderId}`);
      return res.json({ ok: true, ignored: true });
    }

    // Build updates
    const updates = { updated_at: new Date().toISOString() };

    // Update AWB if we didn't have it or it changed
    if (awb && awb !== order.awb_code) {
      updates.awb_code = awb;
      updates.tracking_url = `https://shiprocket.co/tracking/${awb}`;
      updates.courier_name = payload.courier_name || null;
      console.log(`[Shiprocket Webhook] ${order.order_number}: AWB updated to ${awb}`);
    }

    // Map status
    const statusMap = {
      'NEW':                'processing',
      'PICKUP SCHEDULED':   'processing',
      'PICKED UP':          'shipped',
      'IN TRANSIT':         'in_transit',
      'OUT FOR DELIVERY':   'in_transit',
      'DELIVERED':          'delivered',
      'UNDELIVERED':        'returned',
      'RTO INITIATED':      'returned',
      'RTO DELIVERED':      'returned',
      'CANCELED':           'cancelled',
      'CANCELLED':          'cancelled'
    };

    const newStatus = statusMap[(currentStatus || '').toUpperCase()];
    if (newStatus && newStatus !== order.order_status) {
      updates.order_status = newStatus;
      updates.shiprocket_status = currentStatus;

      // Log status transition
      await supabase.from('order_status_history').insert({
        order_id:    order.id,
        from_status: order.order_status,
        to_status:   newStatus,
        source:      'shiprocket_webhook',
        notes:       `Shiprocket: ${currentStatus}`,
        metadata:    payload
      });

      console.log(`[Shiprocket Webhook] ${order.order_number}: ${order.order_status} → ${newStatus}`);
    }

    await supabase.from('orders').update(updates).eq('id', order.id);

    res.json({ ok: true });
  } catch (err) {
    console.error('[Shiprocket Webhook] Error:', err);
    res.status(500).json({ error: err.message });
  }
});



/* ═══════════════════════════════════════════════════════════════
   🔒 ADMIN DASHBOARD API
   ─────────────────────────────────────────────────────────────
   All endpoints require requireAdmin middleware.
   All DB access uses service role key (bypasses RLS safely).
   
   Endpoints:
     GET    /api/admin/check              — is current user admin? (quick check)
     GET    /api/admin/stats              — dashboard summary numbers
     GET    /api/admin/orders             — list orders (paginated, filterable)
     GET    /api/admin/orders/:id         — single order with items
     PATCH  /api/admin/orders/:id         — update order status / tracking / notes
     GET    /api/admin/products           — list all products (inc. inactive)
     GET    /api/admin/products/:id       — single product with variants
     PATCH  /api/admin/products/:id       — update product fields
     POST   /api/admin/products           — create new product
     POST   /api/admin/products/:id/archive   — soft-delete (hide from site)
     POST   /api/admin/products/:id/restore   — un-archive
     DELETE /api/admin/products/:id           — hard-delete (only if no orders)
     POST   /api/admin/products/reorder       — reorder products on homepage
     GET    /api/admin/products/:id/variants  — list variants
     POST   /api/admin/products/:id/variants  — create variant
     POST   /api/admin/products/:id/variants/reorder — reorder variants
     PATCH  /api/admin/variants/:vid          — update variant
     POST   /api/admin/variants/:vid/archive  — archive variant
     DELETE /api/admin/variants/:vid          — hard-delete variant (only if no orders)
     GET    /api/admin/customers          — list customers (paginated, searchable)
     GET    /api/admin/customers/:id      — full detail with orders & LTV
     PATCH  /api/admin/customers/:id      — update customer (name, address, etc)
     GET    /api/admin/coupons            — list coupons
     POST   /api/admin/coupons            — create coupon
     PATCH  /api/admin/coupons/:id        — update coupon
     GET    /api/admin/settings           — all settings rows
     PATCH  /api/admin/settings/:key      — update a setting value
═══════════════════════════════════════════════════════════════ */

// ─── Quick admin check (called on dashboard load) ───────────────
app.get('/api/admin/check', requireAdmin, (req, res) => {
  res.json({ ok: true, email: req.authUser.email });
});

// ─── Dashboard stats ────────────────────────────────────────────
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();

    // Orders today
    const { count: ordersToday } = await supabase
      .from('orders').select('id', { count: 'exact', head: true })
      .gte('created_at', startOfToday);

    // Pending fulfillment = paid but not shipped/delivered
    const { count: pendingFulfillment } = await supabase
      .from('orders').select('id', { count: 'exact', head: true })
      .eq('payment_status', 'paid')
      .in('order_status', ['confirmed', 'processing', 'packed']);

    // Revenue (7d, paid only)
    const { data: revenueRows } = await supabase
      .from('orders').select('total_amount')
      .eq('payment_status', 'paid')
      .gte('created_at', sevenDaysAgo);
    const revenue7d = (revenueRows || []).reduce((s, r) => s + Number(r.total_amount || 0), 0);

    // Low stock products
    const { count: lowStockCount } = await supabase
      .from('products').select('id', { count: 'exact', head: true })
      .eq('stock_status', 'out_of_stock');

    // All-time counts
    const { count: totalOrders } = await supabase
      .from('orders').select('id', { count: 'exact', head: true })
      .eq('payment_status', 'paid');
    const { count: totalCustomers } = await supabase
      .from('customers').select('id', { count: 'exact', head: true });

    res.json({
      ordersToday: ordersToday || 0,
      pendingFulfillment: pendingFulfillment || 0,
      revenue7d: Math.round(revenue7d),
      lowStockCount: lowStockCount || 0,
      totalOrders: totalOrders || 0,
      totalCustomers: totalCustomers || 0
    });
  } catch (err) {
    console.error('[admin/stats]', err);
    res.status(500).json({ error: 'Failed to load stats.' });
  }
});

// ─── Orders list ────────────────────────────────────────────────
app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize) || 25));
    const status = req.query.status; // 'paid' | 'pending' | 'shipped' | etc.
    const search = (req.query.search || '').trim();

    let q = supabase.from('orders').select(
      'id, order_number, customer_name, customer_phone, customer_email, total_amount, payment_status, order_status, awb_code, courier_name, tracking_url, created_at, shipping_city, shipping_pincode',
      { count: 'exact' }
    );

    if (status === 'paid')    q = q.eq('payment_status', 'paid');
    if (status === 'pending') q = q.eq('payment_status', 'pending');
    if (status === 'failed')  q = q.eq('payment_status', 'failed');
    if (status === 'shipped') q = q.in('order_status', ['shipped', 'in_transit']);
    if (status === 'delivered') q = q.eq('order_status', 'delivered');
    if (status === 'cancelled') q = q.eq('order_status', 'cancelled');

    if (search) {
      // Search by order number, customer name, phone, or email
      q = q.or(`order_number.ilike.%${search}%,customer_name.ilike.%${search}%,customer_phone.ilike.%${search}%,customer_email.ilike.%${search}%`);
    }

    const from = (page - 1) * pageSize;
    const to = from + pageSize - 1;
    q = q.order('created_at', { ascending: false }).range(from, to);

    const { data, count, error } = await q;
    if (error) throw error;

    res.json({ orders: data || [], total: count || 0, page, pageSize });
  } catch (err) {
    console.error('[admin/orders]', err);
    res.status(500).json({ error: 'Failed to load orders.' });
  }
});

// ─── Order CSV export (must be defined before /:id to avoid route conflict) ──
app.get('/api/admin/orders/export', requireAdmin, async (req, res) => {
  try {
    const { status, search } = req.query;
    const MAX_ROWS = 5000; // safety cap

    let q = supabase.from('orders').select(
      'id, order_number, customer_name, customer_phone, customer_email, ' +
      'shipping_address, shipping_city, shipping_state, shipping_pincode, ' +
      'subtotal, shipping_fee, discount_amount, total_amount, coupon_code, ' +
      'payment_status, order_status, awb_code, courier_name, tracking_number, tracking_url, ' +
      'created_at, updated_at'
    );

    if (status === 'paid')      q = q.eq('payment_status', 'paid');
    if (status === 'pending')   q = q.eq('payment_status', 'pending');
    if (status === 'failed')    q = q.eq('payment_status', 'failed');
    if (status === 'shipped')   q = q.in('order_status', ['shipped', 'in_transit']);
    if (status === 'delivered') q = q.eq('order_status', 'delivered');
    if (status === 'cancelled') q = q.eq('order_status', 'cancelled');

    if (search) {
      q = q.or(`order_number.ilike.%${search}%,customer_name.ilike.%${search}%,customer_phone.ilike.%${search}%,customer_email.ilike.%${search}%`);
    }

    q = q.order('created_at', { ascending: false }).limit(MAX_ROWS);

    const { data, error } = await q;
    if (error) throw error;

    // Build CSV. Quote all fields, escape internal quotes by doubling them.
    const cols = [
      'order_number','created_at','customer_name','customer_email','customer_phone',
      'shipping_address','shipping_city','shipping_state','shipping_pincode',
      'subtotal','shipping_fee','discount_amount','total_amount','coupon_code',
      'payment_status','order_status','awb_code','courier_name','tracking_number','tracking_url'
    ];
    const escape = (v) => {
      if (v === null || v === undefined) return '';
      const s = String(v).replace(/"/g, '""');
      return `"${s}"`;
    };
    const header = cols.join(',');
    const rows = (data || []).map(r => cols.map(c => escape(r[c])).join(','));
    const csv = [header, ...rows].join('\n');

    const stamp = new Date().toISOString().slice(0, 10);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="muchhad-orders-${stamp}.csv"`);
    res.send('\uFEFF' + csv); // BOM so Excel detects UTF-8 properly
  } catch (err) {
    console.error('[admin/orders/export]', err);
    res.status(500).json({ error: 'Export failed.' });
  }
});

// ─── Daily packing list ─────────────────────────────────────────
// Returns today's (or filtered) paid orders that are ready to pack/ship.
app.get('/api/admin/packing-list', requireAdmin, async (req, res) => {
  try {
    // Default scope: paid orders that are NOT yet shipped/delivered/cancelled
    const { date } = req.query; // YYYY-MM-DD or omit for "all pending"

    let q = supabase.from('orders').select(
      'id, order_number, customer_name, customer_phone, ' +
      'shipping_address, shipping_city, shipping_state, shipping_pincode, ' +
      'total_amount, payment_status, order_status, awb_code, courier_name, created_at, ' +
      'order_items (product_name, size, quantity, unit_price)'
    )
      .eq('payment_status', 'paid')
      .in('order_status', ['confirmed', 'processing', 'packed']);

    if (date) {
      // Only orders placed on this date (UTC start/end)
      const startISO = new Date(`${date}T00:00:00.000Z`).toISOString();
      const endISO   = new Date(`${date}T23:59:59.999Z`).toISOString();
      q = q.gte('created_at', startISO).lte('created_at', endISO);
    }

    q = q.order('created_at', { ascending: true });
    const { data, error } = await q;
    if (error) throw error;

    res.json({ orders: data || [], generated_at: new Date().toISOString() });
  } catch (err) {
    console.error('[admin/packing-list]', err);
    res.status(500).json({ error: 'Failed to load packing list.' });
  }
});

// ─── Bulk status update (atomic loop, status history logged per order) ────
app.post('/api/admin/orders/bulk-status', requireAdmin, async (req, res) => {
  try {
    const ALLOWED_STATUS = ['pending','confirmed','processing','packed','shipped','in_transit','delivered','cancelled','returned'];
    const { order_ids, new_status } = req.body;

    if (!Array.isArray(order_ids) || order_ids.length === 0) {
      return res.status(400).json({ error: 'order_ids array required.' });
    }
    if (order_ids.length > 100) {
      return res.status(400).json({ error: 'Max 100 orders per bulk update.' });
    }
    if (!ALLOWED_STATUS.includes(new_status)) {
      return res.status(400).json({ error: 'Invalid status.' });
    }

    // Fetch current statuses for history logging
    const { data: currentRows } = await supabase
      .from('orders').select('id, order_status').in('id', order_ids);
    const currentMap = {};
    (currentRows || []).forEach(r => currentMap[r.id] = r.order_status);

    // Update all in one query
    const { data: updated, error } = await supabase
      .from('orders')
      .update({ order_status: new_status, updated_at: new Date().toISOString() })
      .in('id', order_ids)
      .select('id, order_number, order_status');
    if (error) throw error;

    // Log status transitions (one history row per actually-changed order)
    const historyRows = (updated || [])
      .filter(o => currentMap[o.id] && currentMap[o.id] !== new_status)
      .map(o => ({
        order_id:    o.id,
        from_status: currentMap[o.id],
        to_status:   new_status,
        source:      'admin_bulk',
        notes:       `Bulk update by ${req.authUser.email}`,
        metadata:    { admin_email: req.authUser.email, batch_size: order_ids.length }
      }));
    if (historyRows.length > 0) {
      await supabase.from('order_status_history').insert(historyRows);
    }

    res.json({ updated_count: (updated || []).length, orders: updated });
  } catch (err) {
    console.error('[admin/orders/bulk-status]', err);
    res.status(500).json({ error: 'Bulk update failed.' });
  }
});

// ─── Resend order confirmation email (admin manual trigger) ──────────
app.post('/api/admin/orders/:id/resend-email', requireAdmin, async (req, res) => {
  try {
    // Force resend: clear the sent_at flag first so sendOrderConfirmation will fire
    await supabase
      .from('orders')
      .update({ confirmation_email_sent_at: null })
      .eq('id', req.params.id);

    const result = await email.sendOrderConfirmation({ supabase, orderId: req.params.id });
    if (result.sent) {
      res.json({ ok: true, message: 'Email sent.' });
    } else {
      res.status(400).json({ error: result.reason });
    }
  } catch (err) {
    console.error('[admin/orders/:id/resend-email]', err);
    res.status(500).json({ error: 'Resend failed.' });
  }
});

// ─── Cancel order (proper workflow with reason) ──────────────────────
app.post('/api/admin/orders/:id/cancel', requireAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    if (!reason || String(reason).trim().length < 3) {
      return res.status(400).json({ error: 'Cancellation reason required (min 3 characters).' });
    }

    // Fetch current state
    const { data: current, error: e1 } = await supabase
      .from('orders').select('id, order_status, payment_status, order_number, notes')
      .eq('id', req.params.id).single();
    if (e1 || !current) return res.status(404).json({ error: 'Order not found.' });
    if (current.order_status === 'cancelled') {
      return res.status(400).json({ error: 'Order is already cancelled.' });
    }
    if (current.order_status === 'delivered') {
      return res.status(400).json({ error: 'Cannot cancel a delivered order. Use returns flow instead.' });
    }

    const cancelNote = `[CANCELLED ${new Date().toISOString().slice(0,10)} by ${req.authUser.email}] ${reason}`;
    const newNotes = current.notes ? `${current.notes}\n${cancelNote}` : cancelNote;

    const { data: updated, error: e2 } = await supabase
      .from('orders')
      .update({
        order_status: 'cancelled',
        notes: newNotes,
        updated_at: new Date().toISOString()
      })
      .eq('id', req.params.id)
      .select()
      .single();
    if (e2) throw e2;

    // Log history
    await supabase.from('order_status_history').insert({
      order_id: req.params.id,
      from_status: current.order_status,
      to_status: 'cancelled',
      source: 'admin_cancel',
      notes: `Cancelled: ${reason}`,
      metadata: { admin_email: req.authUser.email, reason }
    });

    res.json({
      order: updated,
      note: current.payment_status === 'paid'
        ? 'Order cancelled. Customer was charged — issue refund manually via Cashfree dashboard.'
        : 'Order cancelled.'
    });
  } catch (err) {
    console.error('[admin/orders/:id/cancel]', err);
    res.status(500).json({ error: 'Cancel failed.' });
  }
});

// ─── Order detail ───────────────────────────────────────────────
app.get('/api/admin/orders/:id', requireAdmin, async (req, res) => {
  try {
    const { data: order, error: e1 } = await supabase
      .from('orders').select('*').eq('id', req.params.id).maybeSingle();
    if (e1) throw e1;
    if (!order) return res.status(404).json({ error: 'Order not found.' });

    const { data: items } = await supabase
      .from('order_items').select('*')
      .eq('order_id', req.params.id).order('created_at');

    const { data: history } = await supabase
      .from('order_status_history').select('*')
      .eq('order_id', req.params.id).order('created_at', { ascending: false });

    res.json({ order, items: items || [], history: history || [] });
  } catch (err) {
    console.error('[admin/orders/:id]', err);
    res.status(500).json({ error: 'Failed to load order.' });
  }
});

// ─── Update order (status, tracking, notes) ─────────────────────
app.patch('/api/admin/orders/:id', requireAdmin, async (req, res) => {
  try {
    const ALLOWED_STATUS = ['pending','confirmed','processing','packed','shipped','in_transit','delivered','cancelled','returned'];
    const ALLOWED_FIELDS = ['order_status','tracking_number','tracking_url','awb_code','courier_name','notes'];

    // Whitelist what can be updated
    const updates = {};
    for (const k of ALLOWED_FIELDS) {
      if (k in req.body) updates[k] = req.body[k];
    }
    if (updates.order_status && !ALLOWED_STATUS.includes(updates.order_status)) {
      return res.status(400).json({ error: 'Invalid order_status.' });
    }

    // Look up current status for history logging
    const { data: current } = await supabase
      .from('orders').select('order_status').eq('id', req.params.id).single();

    updates.updated_at = new Date().toISOString();
    const { data, error } = await supabase
      .from('orders').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;

    // Log status transition if changed
    if (updates.order_status && current?.order_status && current.order_status !== updates.order_status) {
      await supabase.from('order_status_history').insert({
        order_id:    req.params.id,
        from_status: current.order_status,
        to_status:   updates.order_status,
        source:      'admin_manual',
        notes:       `Changed by ${req.authUser.email}`,
        metadata:    { admin_email: req.authUser.email }
      });
    }

    res.json({ order: data });
  } catch (err) {
    console.error('[admin/orders/:id PATCH]', err);
    res.status(500).json({ error: 'Failed to update order.' });
  }
});

// ─── Products list (inc inactive) ───────────────────────────────
app.get('/api/admin/products', requireAdmin, async (req, res) => {
  try {
    const { include_archived } = req.query;

    // Pull products with their variants in one round-trip
    let q = supabase
      .from('products')
      .select('*, product_variants(id, label, size_value, size_unit, price, mrp, stock_quantity, is_active, archived_at, sku, sort_order, image_url)')
      .order('sort_order', { ascending: true, nullsFirst: false });

    if (include_archived !== 'true') {
      q = q.is('archived_at', null);
    }

    const { data, error } = await q;
    if (error) throw error;
    res.json({ products: data || [] });
  } catch (err) {
    console.error('[admin/products]', err);
    res.status(500).json({ error: 'Failed to load products.' });
  }
});

// ─── Update product ─────────────────────────────────────────────
app.patch('/api/admin/products/:id', requireAdmin, async (req, res) => {
  try {
    const ALLOWED = [
      // Existing fields
      'name','slug','real_name','subtitle','category','price','price_large',
      'discount_percent','weight','badge','image_url','description',
      'is_active','is_combo','stock_status','sort_order',
      // Chat C1: FSSAI / nutritional fields
      'ingredients','shelf_life','storage_instructions','allergens',
      'nutritional_info','manufacturing_info','fssai_license',
      // Chat C1: Visibility toggles
      'show_ingredients','show_nutritional_info','show_allergens','show_shelf_life'
    ];
    const updates = {};
    for (const k of ALLOWED) {
      if (k in req.body) updates[k] = req.body[k];
    }
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update.' });
    }

    const { data, error } = await supabase
      .from('products').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ product: data });
  } catch (err) {
    console.error('[admin/products/:id PATCH]', err);
    res.status(500).json({ error: 'Failed to update product.' });
  }
});

// ─── Create product ─────────────────────────────────────────────
app.post('/api/admin/products', requireAdmin, async (req, res) => {
  try {
    const REQUIRED = ['name', 'slug', 'price'];
    for (const k of REQUIRED) {
      if (!req.body[k]) return res.status(400).json({ error: `Missing required field: ${k}` });
    }

    // slug must be lowercase, hyphens only, no spaces
    const slug = String(req.body.slug).toLowerCase().trim().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
    if (slug.length < 2) return res.status(400).json({ error: 'Slug must be at least 2 characters.' });

    const ALLOWED = [
      'name','real_name','subtitle','category','price','price_large',
      'discount_percent','weight','badge','image_url','description',
      'is_active','is_combo','stock_status','sort_order',
      'ingredients','shelf_life','storage_instructions','allergens',
      'nutritional_info','manufacturing_info','fssai_license',
      'show_ingredients','show_nutritional_info','show_allergens','show_shelf_life'
    ];
    const newProduct = { slug };
    for (const k of ALLOWED) {
      if (k in req.body) newProduct[k] = req.body[k];
    }
    // Sensible defaults
    if (!('is_active'    in newProduct)) newProduct.is_active    = true;
    if (!('stock_status' in newProduct)) newProduct.stock_status = 'in_stock';
    if (!('discount_percent' in newProduct)) newProduct.discount_percent = 0;

    const { data, error } = await supabase.from('products').insert(newProduct).select().single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'A product with this slug already exists.' });
      throw error;
    }
    res.json({ product: data });
  } catch (err) {
    console.error('[admin/products POST]', err);
    res.status(500).json({ error: 'Failed to create product.' });
  }
});

// ─── Image upload (base64-in-JSON, uploads to Supabase Storage) ──
app.post('/api/admin/upload-image', requireAdmin, async (req, res) => {
  try {
    const { filename, content_base64, content_type } = req.body;

    if (!filename || !content_base64 || !content_type) {
      return res.status(400).json({ error: 'filename, content_base64, content_type are required.' });
    }
    if (!/^image\/(webp|jpeg|jpg|png)$/i.test(content_type)) {
      return res.status(400).json({ error: 'Only WebP, JPEG, JPG, PNG allowed.' });
    }

    // Decode base64. Reject if > 5MB.
    const buffer = Buffer.from(content_base64, 'base64');
    if (buffer.length > 5 * 1024 * 1024) {
      return res.status(413).json({ error: 'Image too large. Max 5MB.' });
    }

    // Sanitize filename + add timestamp prefix to avoid collisions
    const cleanName = String(filename).toLowerCase()
      .replace(/[^a-z0-9._-]/g, '-')
      .replace(/-+/g, '-')
      .replace(/^[-.]+|[-.]+$/g, '')
      .slice(-60); // cap length
    const stampedName = `${Date.now()}-${cleanName}`;
    const storagePath = `products/${stampedName}`;

    // Upload to Supabase Storage (service role bypasses RLS)
    const { data, error } = await supabase.storage
      .from('product-images')
      .upload(storagePath, buffer, {
        contentType: content_type,
        upsert: false
      });
    if (error) throw error;

    // Get public URL
    const { data: pub } = supabase.storage.from('product-images').getPublicUrl(storagePath);

    res.json({ path: storagePath, public_url: pub.publicUrl, filename: stampedName });
  } catch (err) {
    console.error('[admin/upload-image]', err);
    res.status(500).json({ error: 'Upload failed: ' + (err.message || 'unknown') });
  }
});

// ─── Customers list ─────────────────────────────────────────────
app.get('/api/admin/customers', requireAdmin, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize) || 25));
    const search = (req.query.search || '').trim();

    let q = supabase.from('customers').select('*', { count: 'exact' });
    if (search) {
      q = q.or(`name.ilike.%${search}%,email.ilike.%${search}%,phone.ilike.%${search}%`);
    }
    const from = (page - 1) * pageSize;
    q = q.order('created_at', { ascending: false }).range(from, from + pageSize - 1);

    const { data, count, error } = await q;
    if (error) throw error;
    res.json({ customers: data || [], total: count || 0, page, pageSize });
  } catch (err) {
    console.error('[admin/customers]', err);
    res.status(500).json({ error: 'Failed to load customers.' });
  }
});

// ═══════════════════════════════════════════════════════════════════
// ─── CHAT C2 NEW ENDPOINTS ─────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════

// ─── Single product detail (with variants) — for product-edit page ──
app.get('/api/admin/products/:id', requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products')
      .select('*, product_variants(id, label, size_value, size_unit, price, mrp, stock_quantity, is_active, archived_at, sku, sort_order, image_url, weight_grams)')
      .eq('id', req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Product not found.' });

    // Sort variants by sort_order on the way out
    if (data.product_variants) {
      data.product_variants.sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0));
    }

    res.json({ product: data });
  } catch (err) {
    console.error('[admin/products/:id GET]', err);
    res.status(500).json({ error: 'Failed to load product.' });
  }
});

// ─── Product archive (soft delete) ──────────────────────────────────
app.post('/api/admin/products/:id/archive', requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products')
      .update({ archived_at: new Date().toISOString(), is_active: false })
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json({ product: data, message: 'Product archived. Hidden from customer site.' });
  } catch (err) {
    console.error('[admin/products/:id/archive]', err);
    res.status(500).json({ error: 'Archive failed.' });
  }
});

// ─── Product restore (un-archive) ───────────────────────────────────
app.post('/api/admin/products/:id/restore', requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products')
      .update({ archived_at: null })
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json({ product: data, message: 'Product restored. Toggle is_active to make it visible.' });
  } catch (err) {
    console.error('[admin/products/:id/restore]', err);
    res.status(500).json({ error: 'Restore failed.' });
  }
});

// ─── Product hard-delete (permanent — guards against orphaning orders) ──
app.delete('/api/admin/products/:id', requireAdmin, async (req, res) => {
  try {
    // Safety: refuse to hard-delete if any order_items reference this product
    const { count, error: countErr } = await supabase
      .from('order_items').select('id', { count: 'exact', head: true })
      .eq('product_id', req.params.id);
    if (countErr) throw countErr;

    if ((count || 0) > 0) {
      return res.status(409).json({
        error: `Cannot permanently delete: ${count} order item(s) reference this product. Archive it instead.`
      });
    }

    // Cascade-deletes variants via FK ON DELETE CASCADE
    const { error } = await supabase.from('products').delete().eq('id', req.params.id);
    if (error) throw error;

    res.json({ message: 'Product permanently deleted.' });
  } catch (err) {
    console.error('[admin/products/:id DELETE]', err);
    res.status(500).json({ error: err.message || 'Delete failed.' });
  }
});

// ─── Product reorder (homepage display order) ───────────────────────
app.post('/api/admin/products/reorder', requireAdmin, async (req, res) => {
  try {
    const { order } = req.body; // [{ id, sort_order }, …]
    if (!Array.isArray(order) || order.length === 0) {
      return res.status(400).json({ error: 'order array required.' });
    }
    if (order.length > 200) {
      return res.status(400).json({ error: 'Too many products in one reorder call.' });
    }

    // Sequential updates (Supabase doesn't have UPSERT-by-multiple-pk-ids without conflict)
    let updated = 0;
    for (const row of order) {
      if (typeof row.id === 'undefined' || typeof row.sort_order === 'undefined') continue;
      const { error } = await supabase
        .from('products')
        .update({ sort_order: Number(row.sort_order) })
        .eq('id', row.id);
      if (!error) updated++;
    }

    res.json({ updated_count: updated });
  } catch (err) {
    console.error('[admin/products/reorder]', err);
    res.status(500).json({ error: 'Reorder failed.' });
  }
});

// ═══════════════════════════════════════════════════════════════════
// ─── PRODUCT VARIANTS CRUD ──────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════

// ─── List variants for a product ────────────────────────────────────
app.get('/api/admin/products/:id/variants', requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('product_variants').select('*')
      .eq('product_id', req.params.id)
      .order('sort_order', { ascending: true });
    if (error) throw error;
    res.json({ variants: data || [] });
  } catch (err) {
    console.error('[admin/products/:id/variants GET]', err);
    res.status(500).json({ error: 'Failed to load variants.' });
  }
});

// ─── Create variant ─────────────────────────────────────────────────
app.post('/api/admin/products/:id/variants', requireAdmin, async (req, res) => {
  try {
    const productId = req.params.id;
    const { label, size_value, size_unit, price, mrp, stock_quantity, sku, weight_grams, sort_order, is_active } = req.body;

    if (!label || String(label).trim().length === 0) {
      return res.status(400).json({ error: 'label is required.' });
    }
    if (price === undefined || price === null || Number(price) < 0) {
      return res.status(400).json({ error: 'price must be 0 or greater.' });
    }

    const newVariant = {
      product_id: Number(productId),
      label: String(label).trim(),
      size_value: size_value === '' || size_value == null ? null : Number(size_value),
      size_unit:  size_unit && String(size_unit).trim() ? String(size_unit).trim() : null,
      price:      Number(price),
      mrp:        mrp === '' || mrp == null ? null : Number(mrp),
      stock_quantity: stock_quantity === '' || stock_quantity == null ? null : Number(stock_quantity),
      sku:        sku && String(sku).trim() ? String(sku).trim() : null,
      weight_grams: weight_grams === '' || weight_grams == null ? null : Number(weight_grams),
      sort_order: sort_order == null ? 0 : Number(sort_order),
      is_active:  is_active !== false
    };

    const { data, error } = await supabase
      .from('product_variants').insert(newVariant).select().single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'A variant with this label already exists for this product.' });
      throw error;
    }
    res.json({ variant: data });
  } catch (err) {
    console.error('[admin/products/:id/variants POST]', err);
    res.status(500).json({ error: 'Failed to create variant.' });
  }
});

// ─── Update variant ─────────────────────────────────────────────────
app.patch('/api/admin/variants/:variantId', requireAdmin, async (req, res) => {
  try {
    const ALLOWED = ['label','size_value','size_unit','price','mrp','stock_quantity','is_active','sku','weight_grams','sort_order','image_url'];
    const updates = {};
    for (const k of ALLOWED) {
      if (k in req.body) updates[k] = req.body[k];
    }
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update.' });
    }

    const { data, error } = await supabase
      .from('product_variants').update(updates).eq('id', req.params.variantId).select().single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'Variant label conflicts with another variant.' });
      throw error;
    }
    res.json({ variant: data });
  } catch (err) {
    console.error('[admin/variants/:variantId PATCH]', err);
    res.status(500).json({ error: 'Failed to update variant.' });
  }
});

// ─── Archive variant (soft delete) ──────────────────────────────────
app.post('/api/admin/variants/:variantId/archive', requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('product_variants')
      .update({ archived_at: new Date().toISOString(), is_active: false })
      .eq('id', req.params.variantId)
      .select()
      .single();
    if (error) throw error;
    res.json({ variant: data, message: 'Variant archived.' });
  } catch (err) {
    console.error('[admin/variants/:variantId/archive]', err);
    res.status(500).json({ error: 'Archive failed.' });
  }
});

// ─── Hard-delete variant (only if no order_items reference it) ──────
app.delete('/api/admin/variants/:variantId', requireAdmin, async (req, res) => {
  try {
    const { count, error: countErr } = await supabase
      .from('order_items').select('id', { count: 'exact', head: true })
      .eq('variant_id', req.params.variantId);
    if (countErr) throw countErr;

    if ((count || 0) > 0) {
      return res.status(409).json({
        error: `Cannot permanently delete: ${count} order item(s) reference this variant. Archive it instead.`
      });
    }

    const { error } = await supabase.from('product_variants').delete().eq('id', req.params.variantId);
    if (error) throw error;
    res.json({ message: 'Variant permanently deleted.' });
  } catch (err) {
    console.error('[admin/variants/:variantId DELETE]', err);
    res.status(500).json({ error: err.message || 'Delete failed.' });
  }
});

// ─── Reorder variants within a product ──────────────────────────────
app.post('/api/admin/products/:id/variants/reorder', requireAdmin, async (req, res) => {
  try {
    const { order } = req.body; // [{ id, sort_order }, …]
    if (!Array.isArray(order) || order.length === 0) {
      return res.status(400).json({ error: 'order array required.' });
    }

    let updated = 0;
    for (const row of order) {
      if (!row.id) continue;
      const { error } = await supabase
        .from('product_variants')
        .update({ sort_order: Number(row.sort_order) || 0 })
        .eq('id', row.id)
        .eq('product_id', req.params.id);  // Prevent reorder spoofing across products
      if (!error) updated++;
    }
    res.json({ updated_count: updated });
  } catch (err) {
    console.error('[admin/products/:id/variants/reorder]', err);
    res.status(500).json({ error: 'Variant reorder failed.' });
  }
});

// ═══════════════════════════════════════════════════════════════════
// ─── CUSTOMER DETAIL + EDIT ─────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════

// ─── Customer detail with orders + LTV ──────────────────────────────
app.get('/api/admin/customers/:id', requireAdmin, async (req, res) => {
  try {
    const { data: customer, error: e1 } = await supabase
      .from('customers').select('*').eq('id', req.params.id).maybeSingle();
    if (e1) throw e1;
    if (!customer) return res.status(404).json({ error: 'Customer not found.' });

    // All orders for this customer
    const { data: orders, error: e2 } = await supabase
      .from('orders')
      .select('id, order_number, total_amount, payment_status, order_status, created_at, awb_code, courier_name')
      .eq('customer_id', req.params.id)
      .order('created_at', { ascending: false });
    if (e2) throw e2;

    // Lifetime value (paid orders only)
    const paidOrders = (orders || []).filter(o => o.payment_status === 'paid');
    const lifetimeValue = paidOrders.reduce((s, o) => s + Number(o.total_amount || 0), 0);
    const lastOrder = orders && orders.length ? orders[0] : null;

    res.json({
      customer,
      orders: orders || [],
      stats: {
        total_orders: (orders || []).length,
        paid_orders: paidOrders.length,
        lifetime_value: Math.round(lifetimeValue),
        last_order_at: lastOrder ? lastOrder.created_at : null
      }
    });
  } catch (err) {
    console.error('[admin/customers/:id GET]', err);
    res.status(500).json({ error: 'Failed to load customer.' });
  }
});

// ─── Update customer (admin can fix typos in addresses, names) ──────
app.patch('/api/admin/customers/:id', requireAdmin, async (req, res) => {
  try {
    const ALLOWED = ['name','email','address','city','state','pincode','notes'];
    const updates = {};
    for (const k of ALLOWED) {
      if (k in req.body) updates[k] = req.body[k];
    }
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update.' });
    }

    // Normalize email if present
    if ('email' in updates && updates.email) {
      updates.email = String(updates.email).trim().toLowerCase();
    }

    updates.updated_at = new Date().toISOString();
    const { data, error } = await supabase
      .from('customers').update(updates).eq('id', req.params.id).select().single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'Email or phone already used by another customer.' });
      throw error;
    }
    res.json({ customer: data });
  } catch (err) {
    console.error('[admin/customers/:id PATCH]', err);
    res.status(500).json({ error: 'Failed to update customer.' });
  }
});

// ═══════════════════════════════════════════════════════════════════
// ─── END CHAT C2 NEW ENDPOINTS ──────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════

// ─── Coupons ────────────────────────────────────────────────────
app.get('/api/admin/coupons', requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('coupons').select('*').order('created_at', { ascending: false });
    if (error) throw error;

    // Enrich with actual redemption counts
    const enriched = await Promise.all((data || []).map(async c => {
      const { count } = await supabase.from('coupon_redemptions')
        .select('id', { count: 'exact', head: true }).eq('coupon_id', c.id);
      return { ...c, actual_uses: count || 0 };
    }));
    res.json({ coupons: enriched });
  } catch (err) {
    console.error('[admin/coupons]', err);
    res.status(500).json({ error: 'Failed to load coupons.' });
  }
});

app.post('/api/admin/coupons', requireAdmin, async (req, res) => {
  try {
    const { code, discount_type, discount_value, min_order_value, max_uses, expires_at, is_active } = req.body;

    if (!code || !discount_type || !discount_value) {
      return res.status(400).json({ error: 'code, discount_type and discount_value are required.' });
    }
    if (!['percentage','flat'].includes(discount_type)) {
      return res.status(400).json({ error: "discount_type must be 'percentage' or 'flat'." });
    }

    const { data, error } = await supabase.from('coupons').insert({
      code: String(code).toUpperCase().trim(),
      discount_type,
      discount_value: Number(discount_value),
      min_order_value: Number(min_order_value) || 0,
      max_uses: max_uses ? Number(max_uses) : null,
      expires_at: expires_at || null,
      is_active: is_active !== false
    }).select().single();

    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'A coupon with this code already exists.' });
      throw error;
    }
    res.json({ coupon: data });
  } catch (err) {
    console.error('[admin/coupons POST]', err);
    res.status(500).json({ error: 'Failed to create coupon.' });
  }
});

app.patch('/api/admin/coupons/:id', requireAdmin, async (req, res) => {
  try {
    const ALLOWED = ['is_active','expires_at','max_uses','min_order_value','discount_value'];
    const updates = {};
    for (const k of ALLOWED) if (k in req.body) updates[k] = req.body[k];

    const { data, error } = await supabase
      .from('coupons').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ coupon: data });
  } catch (err) {
    console.error('[admin/coupons/:id PATCH]', err);
    res.status(500).json({ error: 'Failed to update coupon.' });
  }
});

// ─── Settings ───────────────────────────────────────────────────
app.get('/api/admin/settings', requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('settings').select('*').order('key');
    if (error) throw error;
    res.json({ settings: data || [] });
  } catch (err) {
    console.error('[admin/settings]', err);
    res.status(500).json({ error: 'Failed to load settings.' });
  }
});

app.patch('/api/admin/settings/:key', requireAdmin, async (req, res) => {
  try {
    if (!('value' in req.body)) return res.status(400).json({ error: 'Missing value.' });
    const { data, error } = await supabase
      .from('settings').update({ value: req.body.value }).eq('key', req.params.key).select().single();
    if (error) throw error;
    res.json({ setting: data });
  } catch (err) {
    console.error('[admin/settings/:key PATCH]', err);
    res.status(500).json({ error: 'Failed to update setting.' });
  }
});

/* ── Start ── */
app.listen(PORT, () => {
  console.log(`\n  🍪 Muchhad API running on port ${PORT}`);
  console.log(`  📦 Cashfree: ${CF.baseUrl}`);
  console.log(`  🌐 API URL:  ${API_BASE_URL}`);
  console.log(`  🗄️  Supabase: ${process.env.SUPABASE_URL}`);
  console.log(`  🔒 Mode:     ${IS_PROD ? 'PRODUCTION' : 'DEVELOPMENT'}\n`);
});