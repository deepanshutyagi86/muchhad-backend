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
  verify: (req, res, buf) => {
    // Save raw bytes so the Cashfree webhook handler can verify HMAC
    req.rawBody = buf.toString('utf8');
  }
}));
app.use(express.urlencoded({ extended: true }));

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
function getMRP(product, size) {
  if (size === '350g' && product.price_large) return Number(product.price_large);
  return Number(product.price);
}

function getUnitPrice(product, size) {
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

    /* ── Fetch product data from DB ── */
    const productIds = items.map(i => i.product_id);
    const { data: products, error: prodErr } = await supabase
      .from('products')
      .select('id, name, slug, price, price_large, discount_percent, stock_status, is_active, is_combo')
      .in('id', productIds);

    if (prodErr) throw prodErr;

    const productMap = {};
    products.forEach(p => { productMap[p.id] = p; });

    /* ── Validate each item ── */
    for (const item of items) {
      const prod = productMap[item.product_id];
      if (!prod) return res.status(400).json({ error: `Product #${item.product_id} not found.` });
      if (!prod.is_active) return res.status(400).json({ error: `${prod.name} is currently unavailable.` });
      if (prod.stock_status === 'out_of_stock') return res.status(400).json({ error: `${prod.name} is out of stock.` });

      const size = item.size || DEFAULT_SIZE;
      if (!VALID_SIZES.includes(size)) {
        return res.status(400).json({ error: `Invalid size "${size}" for ${prod.name}.` });
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
      const unitPrice = getUnitPrice(prod, size);
      const lineTotal = unitPrice * item.quantity;
      subtotal += lineTotal;
      return {
        product_id:   prod.id,
        product_name: prod.name,
        quantity:     item.quantity,
        unit_price:   unitPrice,
        line_total:   lineTotal,
        size:         size,
        item_options: item.options || item.item_options || {}
      };
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
    const { data: rpcResult, error: rpcErr } = await supabase.rpc('create_order_transactional', {
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
      console.error('[create_order_transactional] failed:', rpcErr);
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

      // TODO Step 9: send confirmation email here
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
     PATCH  /api/admin/products/:id       — update product fields
     GET    /api/admin/customers          — list customers (paginated, searchable)
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
    const { data, error } = await supabase
      .from('products').select('*').order('sort_order', { nullsFirst: false });
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
    const ALLOWED = ['name','slug','real_name','subtitle','category','price','price_large','discount_percent','weight','badge','image_url','description','is_active','is_combo','stock_status','sort_order'];
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