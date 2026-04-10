/* ═══════════════════════════════════════════════════════════════
   Muchhad Backend · Express Server
   ─────────────────────────────────────────────────────────────
   Handles: Cashfree payments, order management, coupon validation
   Updated v3:
     • Pricing uses discount_percent (dynamic % off from DB)
     • Size variants 200g / 350g (was 150g / 350g)
     • Reads item.options (frontend name), stores as item_options
     • Email optional, falls back to support@muchhadeats.in
     • notify_url uses API_BASE_URL (was FRONTEND_URL — bug)
═══════════════════════════════════════════════════════════════ */

require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const helmet   = require('helmet');
const crypto   = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app  = express();
const PORT = process.env.PORT || 3001;

const SUPPORT_EMAIL = 'support@muchhadeats.in';
const VALID_SIZES   = ['200g', '350g'];
const DEFAULT_SIZE  = '200g';

/* ── Supabase (service role — bypasses RLS) ── */
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

/* ── Cashfree config ── */
const CF = {
  appId:     process.env.CASHFREE_APP_ID,
  secretKey: process.env.CASHFREE_SECRET_KEY,
  baseUrl:   process.env.CASHFREE_BASE_URL   || 'https://sandbox.cashfree.com/pg',
  version:   process.env.CASHFREE_API_VERSION || '2023-08-01'
};

/* ── URLs ──
   API_BASE_URL = this backend (where Cashfree sends webhooks)
   FRONTEND_URL = the website (where users are redirected after payment)
*/
const API_BASE_URL = process.env.API_BASE_URL || 'https://api.muchhadeats.in';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://muchhadeats.in';

/* ── Middleware ── */
app.use(helmet());
app.use(cors({
  origin: [
    FRONTEND_URL,
    'https://muchhadeats.in',
    'http://muchhadeats.in',
    'https://www.muchhadeats.in',
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST'],
  credentials: true
}));
app.use(express.json({
  verify: (req, res, buf) => {
    // Save the raw request body bytes so the Cashfree webhook handler
    // can verify the HMAC signature against the EXACT bytes Cashfree sent.
    req.rawBody = buf.toString('utf8');
  }
}));
app.use(express.urlencoded({ extended: true }));

/* ── Request logging ── */
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});


/* ═══════════════════════════════════════════════════════════════
   PRICE HELPERS (mirror of frontend logic — single source = DB)
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


/* ──────────────────────────────────────────────────────────────
   POST /api/orders/create
   ──────────────────────────────────────────────────────────────
   Body: {
     customer: { name, phone, address, city, state, pincode, email? },
     items: [{ product_id, quantity, size, options }],
     coupon_code?: string
   }
────────────────────────────────────────────────────────────── */
app.post('/api/orders/create', async (req, res) => {
  try {
    const { customer, items, coupon_code } = req.body;

    /* ── Validate input (email is optional now) ── */
    if (!customer?.name || !customer?.phone || !customer?.address) {
      return res.status(400).json({ error: 'Missing required customer fields.' });
    }
    if (!/^\d{10}$/.test(customer.phone)) {
      return res.status(400).json({ error: 'Invalid phone number.' });
    }
    if (!items?.length) {
      return res.status(400).json({ error: 'Cart is empty.' });
    }

    const customerEmail = customer.email?.trim() || SUPPORT_EMAIL;

    /* ── Fetch product data from DB (NEVER trust frontend prices) ── */
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

      /* combo-pick-4 must have exactly 4 flavour selections.
         Frontend sends them under `options`; accept legacy `item_options` too. */
      if (prod.slug === 'combo-pick-4') {
        const opts = item.options || item.item_options || {};
        const selections = opts.selected_flavors || [];
        if (!Array.isArray(selections) || selections.length !== 4) {
          return res.status(400).json({ error: 'Pick Any 4 combo requires exactly 4 flavour selections.' });
        }
        /* Validate those flavours actually exist and are individual products */
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

    /* ── Calculate totals server-side using discount_percent ── */
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
        /* store under item_options to match DB column; accept either input name */
        item_options: item.options || item.item_options || {}
      };
    });

    /* ── Apply coupon if provided ── */
    let discount = 0;
    let appliedCoupon = null;
    if (coupon_code) {
      const { data: coupon } = await supabase
        .from('coupons')
        .select('*')
        .eq('code', coupon_code.toUpperCase())
        .eq('is_active', true)
        .single();

      if (coupon) {
        const now = new Date();
        const notExpired = !coupon.expires_at || new Date(coupon.expires_at) > now;
        const notMaxed   = !coupon.max_uses || coupon.times_used < coupon.max_uses;
        const meetsMin   = subtotal >= (coupon.min_order_value || 0);

        if (notExpired && notMaxed && meetsMin) {
          appliedCoupon = coupon;
          discount = coupon.discount_type === 'percentage'
            ? Math.round(subtotal * coupon.discount_value / 100)
            : coupon.discount_value;
          discount = Math.min(discount, subtotal);
        }
      }
    }

    const shippingFee = subtotal >= 499 ? 0 : 49;
    const totalAmount = subtotal - discount + shippingFee;

    /* ── Upsert customer by PHONE (phone is the real unique contact) ── */
    const { data: cust } = await supabase
      .from('customers')
      .upsert({
        name:    customer.name,
        email:   customerEmail,
        phone:   customer.phone,
        address: customer.address,
        city:    customer.city || '',
        state:   customer.state || '',
        pincode: customer.pincode || ''
      }, { onConflict: 'phone' })
      .select('id')
      .single();

    /* ── Create order row ── */
    const { data: order, error: orderErr } = await supabase
      .from('orders')
      .insert({
        customer_id:      cust?.id || null,
        customer_name:    customer.name,
        customer_email:   customerEmail,
        customer_phone:   customer.phone,
        shipping_address: customer.address,
        shipping_city:    customer.city || '',
        shipping_state:   customer.state || '',
        shipping_pincode: customer.pincode || '',
        subtotal,
        shipping_fee:     shippingFee,
        discount_amount:  discount,
        total_amount:     totalAmount,
        coupon_code:      appliedCoupon?.code || null,
        payment_status:   'pending',
        order_status:     'pending'
      })
      .select('id, order_number')
      .single();

    if (orderErr) throw orderErr;

    /* ── Insert order items ── */
    const itemRows = orderItems.map(i => ({ ...i, order_id: order.id }));
    const { error: itemsErr } = await supabase.from('order_items').insert(itemRows);
    if (itemsErr) throw itemsErr;

    /* ── Increment coupon usage ── */
    if (appliedCoupon) {
      await supabase.from('coupons')
        .update({ times_used: appliedCoupon.times_used + 1 })
        .eq('id', appliedCoupon.id);
    }

    /* ── Create Cashfree payment session ── */
    const cfOrderPayload = {
      order_id:       order.id,
      order_amount:   totalAmount,
      order_currency: 'INR',
      customer_details: {
        customer_id:    (cust?.id || order.id).toString(),
        customer_name:  customer.name,
        customer_email: customerEmail,
        customer_phone: customer.phone
      },
      order_meta: {
        return_url: `${FRONTEND_URL}/order-status?order_id=${order.id}`,
        /* Webhooks hit the BACKEND, not the frontend */
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
      return res.status(502).json({
        error: 'Payment gateway error. Your order is saved — please try again.',
        order_id: order.id,
        order_number: order.order_number
      });
    }

    await supabase.from('orders')
      .update({ cashfree_order_id: cfData.cf_order_id || cfData.order_id })
      .eq('id', order.id);

    res.json({
      success:             true,
      order_id:            order.id,
      order_number:        order.order_number,
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
   POST /api/payments/webhook
   Called by Cashfree. Source of truth for payment status.
────────────────────────────────────────────────────────────── */
app.post('/api/payments/webhook', async (req, res) => {
  try {
    const signature = req.headers['x-webhook-signature'];
    const ts        = req.headers['x-webhook-timestamp'];
    const rawBody   = req.rawBody;

    if (!signature || !ts || !rawBody) {
      console.warn('[Webhook] Missing signature, timestamp, or body — rejecting.');
      return res.status(400).json({ error: 'Missing signature data' });
    }

    // Reject webhooks older than 5 minutes (replay-attack protection)
    const ageSeconds = (Date.now() / 1000) - Number(ts);
    if (Number.isNaN(ageSeconds) || ageSeconds > 300 || ageSeconds < -60) {
      console.warn('[Webhook] Stale or future-dated timestamp — rejecting.');
      return res.status(401).json({ error: 'Stale webhook' });
    }

    const expectedSig = crypto
      .createHmac('sha256', CF.secretKey)
      .update(ts + rawBody)
      .digest('base64');

    // Constant-time comparison to prevent timing attacks
    const sigBuf = Buffer.from(signature, 'base64');
    const expBuf = Buffer.from(expectedSig, 'base64');
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      console.warn('[Webhook] Invalid signature — rejecting.');
      return res.status(401).json({ error: 'Invalid signature' });
    }

    const { data } = req.body;
    if (!data?.order?.order_id) {
      return res.status(400).json({ error: 'Missing order ID in webhook' });
    }

    const orderId = data.order.order_id;
    const paymentStatus = data.payment?.payment_status;
    const cfPaymentId   = data.payment?.cf_payment_id;

    let dbPaymentStatus = 'pending';
    let dbOrderStatus   = 'pending';

    if (paymentStatus === 'SUCCESS') {
      dbPaymentStatus = 'paid';
      dbOrderStatus   = 'confirmed';
    } else if (paymentStatus === 'FAILED' || paymentStatus === 'CANCELLED' || paymentStatus === 'USER_DROPPED') {
      dbPaymentStatus = 'failed';
      dbOrderStatus   = 'cancelled';
    }

    const { error } = await supabase.from('orders').update({
      payment_status:      dbPaymentStatus,
      order_status:        dbOrderStatus,
      cashfree_payment_id: cfPaymentId?.toString() || null
    }).eq('id', orderId);

    if (error) {
      console.error('[Webhook] DB update failed:', error);
      return res.status(500).json({ error: 'DB update failed' });
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
   Frontend polling endpoint. Final truth is the webhook above.
────────────────────────────────────────────────────────────── */
app.post('/api/payments/verify', async (req, res) => {
  try {
    const { order_id } = req.body;
    if (!order_id) return res.status(400).json({ error: 'Missing order_id' });

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
      await supabase.from('orders').update({
        payment_status:      'paid',
        order_status:        'confirmed',
        cashfree_payment_id: successfulPayment.cf_payment_id?.toString()
      }).eq('id', order_id);

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
app.post('/api/coupons/validate', async (req, res) => {
  try {
    const { code, subtotal } = req.body;
    if (!code) return res.status(400).json({ error: 'No coupon code provided.' });

    const { data: coupon } = await supabase
      .from('coupons')
      .select('*')
      .eq('code', code.toUpperCase())
      .eq('is_active', true)
      .single();

    if (!coupon) return res.json({ valid: false, message: 'Invalid coupon code.' });

    const now = new Date();
    if (coupon.expires_at && new Date(coupon.expires_at) < now) {
      return res.json({ valid: false, message: 'This coupon has expired.' });
    }
    if (coupon.max_uses && coupon.times_used >= coupon.max_uses) {
      return res.json({ valid: false, message: 'This coupon has been fully redeemed.' });
    }
    if (subtotal < (coupon.min_order_value || 0)) {
      return res.json({ valid: false, message: `Minimum order ₹${coupon.min_order_value} required.` });
    }

    const discount = coupon.discount_type === 'percentage'
      ? Math.round(subtotal * coupon.discount_value / 100)
      : coupon.discount_value;

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
   POST /api/analytics/event
────────────────────────────────────────────────────────────── */
app.post('/api/analytics/event', async (req, res) => {
  try {
    const { event_type, event_data, session_id } = req.body;
    await supabase.from('analytics_events').insert({
      event_type,
      event_data:  event_data || {},
      session_id:  session_id || null,
      user_agent:  req.headers['user-agent'] || '',
      ip_address:  req.ip
    });
    res.json({ ok: true });
  } catch (err) {
    res.json({ ok: false });
  }
});


/* ── Start ── */
app.listen(PORT, () => {
  console.log(`\n  🍪 Muchhad API running on port ${PORT}`);
  console.log(`  📦 Cashfree: ${CF.baseUrl}`);
  console.log(`  🌐 API URL:  ${API_BASE_URL}`);
  console.log(`  🗄️  Supabase: ${process.env.SUPABASE_URL}\n`);
});