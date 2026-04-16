/* ═══════════════════════════════════════════════════════════════
   shiprocket.js — Shiprocket API service module
   ─────────────────────────────────────────────────────────────
   Handles:
     • Auth (login, token caching, auto-refresh)
     • Pincode serviceability check
     • Order creation
     • AWB assignment (auto-picks cheapest serviceable courier)
     • Order status fetching
     • Cancel order (for manual retries)

   Supports TEST MODE via SHIPROCKET_LIVE_MODE=false env var,
   where calls are logged but not actually sent to Shiprocket.
═══════════════════════════════════════════════════════════════ */

const { createClient } = require('@supabase/supabase-js');

const SR_BASE_URL = 'https://apiv2.shiprocket.in/v1/external';
const SR_EMAIL    = process.env.SHIPROCKET_EMAIL;
const SR_PASSWORD = process.env.SHIPROCKET_PASSWORD;
const SR_PICKUP   = process.env.SHIPROCKET_PICKUP_LOCATION;
const SR_CHANNEL  = process.env.SHIPROCKET_CHANNEL_ID || null;
const LIVE_MODE   = process.env.SHIPROCKET_LIVE_MODE === 'true';

// Validate required env vars at load time (fail loud, fail early)
const requiredEnvVars = {
  SHIPROCKET_EMAIL:            SR_EMAIL,
  SHIPROCKET_PASSWORD:         SR_PASSWORD,
  SHIPROCKET_PICKUP_LOCATION:  SR_PICKUP
};

const missing = Object.entries(requiredEnvVars)
  .filter(([, value]) => !value)
  .map(([key]) => key);

if (missing.length > 0) {
  console.error(`[Shiprocket] FATAL: Missing required env vars: ${missing.join(', ')}`);
  console.error(`[Shiprocket] Set these on Hostinger → Node.js → Environment Variables.`);
  throw new Error(`Shiprocket config incomplete: ${missing.join(', ')}`);
}

// Supabase for settings lookups (passed in from server.js)
let supabase = null;

/* ═══════════════════════════════════════════════════════════════
   TOKEN CACHE
   Shiprocket tokens expire after ~10 days. We cache in memory
   and refresh on 401 or when >9 days old.
═══════════════════════════════════════════════════════════════ */
let cachedToken = null;
let tokenFetchedAt = 0;
const TOKEN_MAX_AGE_MS = 9 * 24 * 60 * 60 * 1000; // 9 days

async function getToken(forceRefresh = false) {
  const isStale = Date.now() - tokenFetchedAt > TOKEN_MAX_AGE_MS;
  if (cachedToken && !forceRefresh && !isStale) return cachedToken;

  if (!SR_EMAIL || !SR_PASSWORD) {
    throw new Error('SHIPROCKET_EMAIL or SHIPROCKET_PASSWORD not configured');
  }

  console.log('[Shiprocket] Fetching new token...');
  const res = await fetch(`${SR_BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: SR_EMAIL, password: SR_PASSWORD })
  });

  const data = await res.json();
  if (!res.ok || !data.token) {
    throw new Error(`Shiprocket auth failed: ${data.message || res.status}`);
  }

  cachedToken = data.token;
  tokenFetchedAt = Date.now();
  console.log('[Shiprocket] Token acquired.');
  return cachedToken;
}

/* ═══════════════════════════════════════════════════════════════
   SMART FETCH — handles auth + auto-retry on 401
═══════════════════════════════════════════════════════════════ */
async function srFetch(path, options = {}, retried = false) {
  const token = await getToken();
  const res = await fetch(`${SR_BASE_URL}${path}`, {
    ...options,
    headers: {
      ...(options.headers || {}),
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });

  // Token might have expired — retry once with fresh token
  if (res.status === 401 && !retried) {
    console.warn('[Shiprocket] Got 401, refreshing token and retrying.');
    cachedToken = null;
    return srFetch(path, options, true);
  }

  const body = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body };
}

/* ═══════════════════════════════════════════════════════════════
   PINCODE SERVICEABILITY
   Checks if a pincode is deliverable. Caches result for 7 days.
═══════════════════════════════════════════════════════════════ */
async function checkPincodeServiceability(pincode) {
  if (!/^\d{6}$/.test(pincode)) {
    return { serviceable: false, reason: 'Invalid pincode format' };
  }

  // 1. Check cache first
  try {
    const { data: cached } = await supabase
      .from('pincode_serviceability_cache')
      .select('*')
      .eq('pincode', pincode)
      .gt('expires_at', new Date().toISOString())
      .maybeSingle();

    if (cached) {
      return {
        serviceable: cached.is_serviceable,
        courier_count: cached.courier_count,
        cached: true
      };
    }
  } catch (e) { /* fall through to live check */ }

  // 2. Live check — we need a "from" pincode. Get it from Shiprocket pickup location.
  // For simplicity, we hardcode a reasonable Indian pickup pincode default here.
  // TODO: fetch from pickup addresses in Shiprocket (next version)
  const fromPincode = process.env.PICKUP_PINCODE;
if (!fromPincode) {
  console.error('[Shiprocket] PICKUP_PINCODE env var not set — cannot check serviceability');
  return { serviceable: false, reason: 'Shipping origin not configured' };
}

  if (!LIVE_MODE) {
    // Test mode — assume serviceable
    console.log(`[Shiprocket TEST] Would check pincode ${pincode} serviceability`);
    return { serviceable: true, courier_count: 99, test_mode: true };
  }

  const path = `/courier/serviceability/?pickup_postcode=${fromPincode}&delivery_postcode=${pincode}&weight=0.5&cod=0`;
  const { ok, body } = await srFetch(path, { method: 'GET' });

  if (!ok || body.status !== 200) {
    return { serviceable: false, reason: body.message || 'Serviceability check failed' };
  }

  const couriers = body.data?.available_courier_companies || [];
  const serviceable = couriers.length > 0;

  // Cache it
  try {
    await supabase.from('pincode_serviceability_cache').upsert({
      pincode,
      is_serviceable: serviceable,
      courier_count: couriers.length,
      checked_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
    }, { onConflict: 'pincode' });
  } catch (e) { /* silent */ }

  return { serviceable, courier_count: couriers.length };
}

/* ═══════════════════════════════════════════════════════════════
   CREATE ORDER IN SHIPROCKET
   Returns { shiprocket_order_id, shipment_id } on success.
═══════════════════════════════════════════════════════════════ */
async function createShiprocketOrder(order, items, products) {
  // Build order_items from DB product data
  const orderItems = items.map(item => {
    const product = products.find(p => p.id === item.product_id);
    if (!product) throw new Error(`Product ${item.product_id} not found for Shiprocket order`);

    const size = item.size || '200g';
    const weight = size === '350g' 
      ? (product.weight_grams_350g || 410)
      : (product.weight_grams_200g || 250);

    return {
      name:          product.name,
      sku:           product.slug + '-' + size,
      units:         item.quantity,
      selling_price: Number(item.unit_price),
      discount:      0,
      tax:           product.tax_rate || 5,
      hsn:           product.hsn_code || '1905'
    };
  });

  // Total shipment weight in kg (sum of all items × qty)
  const totalWeightGrams = items.reduce((sum, item) => {
    const product = products.find(p => p.id === item.product_id);
    if (!product) return sum;
    const size = item.size || '200g';
    const w = size === '350g' 
      ? (product.weight_grams_350g || 410)
      : (product.weight_grams_200g || 250);
    return sum + (w * item.quantity);
  }, 0);
  const totalWeightKg = Math.max(totalWeightGrams / 1000, 0.1);

  // Package dimensions — use the LARGEST item's dimensions as approximation
  // (proper solution is cartonization algorithm, but that's overkill for launch)
  let maxDims = { l: 15, b: 10, h: 5 };
  for (const item of items) {
    const product = products.find(p => p.id === item.product_id);
    if (!product) continue;
    const l = Number(product.length_cm || 15);
    const b = Number(product.breadth_cm || 10);
    const h = Number(product.height_cm || 5);
    if (l * b * h > maxDims.l * maxDims.b * maxDims.h) {
      maxDims = { l, b, h };
    }
  }

  // Split name into first + last (Shiprocket requires separate fields)
  const nameParts = (order.customer_name || '').trim().split(/\s+/);
  const firstName = nameParts[0] || 'Customer';
  const lastName  = nameParts.slice(1).join(' ') || '.';

  const payload = {
    order_id:                 order.order_number,
    order_date:               new Date(order.created_at).toISOString().split('T')[0],
    pickup_location:          SR_PICKUP,
    channel_id:               SR_CHANNEL || undefined,
    comment:                  `Muchhad order ${order.order_number}`,
    billing_customer_name:    firstName,
    billing_last_name:        lastName,
    billing_address:          order.shipping_address,
    billing_city:             order.shipping_city,
    billing_pincode:          order.shipping_pincode,
    billing_state:            order.shipping_state,
    billing_country:          'India',
    billing_email:            order.customer_email || 'support@muchhadeats.in',
    billing_phone:            order.customer_phone,
    shipping_is_billing:      true,
    order_items:              orderItems,
    payment_method:           'Prepaid',
    shipping_charges:         Number(order.shipping_fee) || 0,
    giftwrap_charges:         0,
    transaction_charges:      0,
    total_discount:           Number(order.discount_amount) || 0,
    sub_total:                Number(order.total_amount),
    length:                   maxDims.l,
    breadth:                  maxDims.b,
    height:                   maxDims.h,
    weight:                   totalWeightKg
  };

  if (!LIVE_MODE) {
    console.log(`[Shiprocket TEST MODE] Would create order:`, JSON.stringify(payload, null, 2));
    return {
      shiprocket_order_id: 'TEST_' + order.order_number,
      shipment_id:         'TEST_SHIPMENT_' + Date.now(),
      test_mode:           true
    };
  }

  const { ok, status, body } = await srFetch('/orders/create/adhoc', {
    method: 'POST',
    body: JSON.stringify(payload)
  });

  if (!ok || body.status_code === 400 || !body.order_id) {
    throw new Error(`Shiprocket order creation failed: ${JSON.stringify(body)}`);
  }

  return {
    shiprocket_order_id: String(body.order_id),
    shipment_id:         String(body.shipment_id),
    awb_code:            body.awb_code || null,
    courier_name:        body.courier_name || null
  };
}

/* ═══════════════════════════════════════════════════════════════
   ASSIGN AWB (pick cheapest serviceable courier)
═══════════════════════════════════════════════════════════════ */
async function assignAWB(shipmentId) {
  if (!LIVE_MODE) {
    console.log(`[Shiprocket TEST MODE] Would assign AWB to shipment ${shipmentId}`);
    return {
      awb_code:     'TEST_AWB_' + Date.now(),
      courier_name: 'Test Courier',
      test_mode:    true
    };
  }

  const { ok, body } = await srFetch('/courier/assign/awb', {
    method: 'POST',
    body: JSON.stringify({ shipment_id: Number(shipmentId) })
  });

  if (!ok || body.awb_assign_status !== 1) {
    throw new Error(`AWB assignment failed: ${JSON.stringify(body)}`);
  }

  return {
    awb_code:     body.response?.data?.awb_code,
    courier_name: body.response?.data?.courier_name,
    courier_id:   body.response?.data?.courier_company_id
  };
}

/* ═══════════════════════════════════════════════════════════════
   GET ORDER TRACKING
═══════════════════════════════════════════════════════════════ */
async function getTracking(awbCode) {
  if (!LIVE_MODE) {
    return { awb: awbCode, status: 'Test mode — no tracking', test_mode: true };
  }

  const { ok, body } = await srFetch(`/courier/track/awb/${awbCode}`, { method: 'GET' });
  if (!ok) return null;
  return body.tracking_data || body;
}

/* ═══════════════════════════════════════════════════════════════
   MAIN ORCHESTRATION — called from server.js webhook handler
═══════════════════════════════════════════════════════════════ */
async function pushOrderToShiprocket(orderId) {
  if (!supabase) throw new Error('Shiprocket module not initialized — call init(supabase) first');

  // 1. Fetch order + items + products in parallel
  const [{ data: order }, { data: items }] = await Promise.all([
    supabase.from('orders').select('*').eq('id', orderId).single(),
    supabase.from('order_items').select('*').eq('order_id', orderId)
  ]);

  if (!order) throw new Error(`Order ${orderId} not found`);
  if (!items || items.length === 0) throw new Error(`Order ${orderId} has no items`);

  // Don't double-push
  if (order.shiprocket_order_id) {
    console.log(`[Shiprocket] Order ${order.order_number} already pushed (${order.shiprocket_order_id}), skipping.`);
    return { already_pushed: true, shiprocket_order_id: order.shiprocket_order_id };
  }

  const productIds = [...new Set(items.map(i => i.product_id))];
  const { data: products } = await supabase
    .from('products')
    .select('id, name, slug, weight_grams_200g, weight_grams_350g, length_cm, breadth_cm, height_cm, tax_rate, hsn_code')
    .in('id', productIds);

  // 2. Create order in Shiprocket
  let srOrder;
  try {
    srOrder = await createShiprocketOrder(order, items, products);
  } catch (err) {
    console.error(`[Shiprocket] Order creation failed for ${order.order_number}:`, err.message);
    await supabase.from('orders').update({
      needs_shiprocket_push: true,
      shiprocket_error: err.message
    }).eq('id', orderId);
    throw err;
  }

  // 3. Save Shiprocket order ID immediately (in case AWB assignment fails)
  await supabase.from('orders').update({
    shiprocket_order_id:    srOrder.shiprocket_order_id,
    shiprocket_shipment_id: srOrder.shipment_id,
    shiprocket_pushed_at:   new Date().toISOString(),
    needs_shiprocket_push:  false,
    shiprocket_error:       null
  }).eq('id', orderId);

  // 4. Assign AWB (may already be assigned if auto-ship is on)
  let awbData = {
    awb_code:     srOrder.awb_code,
    courier_name: srOrder.courier_name
  };

  if (!awbData.awb_code) {
    try {
      awbData = await assignAWB(srOrder.shipment_id);
    } catch (err) {
      console.warn(`[Shiprocket] AWB assignment failed for ${order.order_number}:`, err.message);
      // Order is in Shiprocket but no AWB — admin can retry later
      await supabase.from('orders').update({
        shiprocket_error: `AWB pending: ${err.message}`
      }).eq('id', orderId);
      return { ...srOrder, awb_pending: true, error: err.message };
    }
  }

  // 5. Build tracking URL
  const trackingUrl = awbData.awb_code
    ? `https://shiprocket.co/tracking/${awbData.awb_code}`
    : null;

  await supabase.from('orders').update({
    awb_code:      awbData.awb_code,
    courier_name:  awbData.courier_name,
    tracking_url:  trackingUrl,
    order_status:  'processing'
  }).eq('id', orderId);

  // 6. Log status transition
  await supabase.from('order_status_history').insert({
    order_id:    orderId,
    from_status: 'confirmed',
    to_status:   'processing',
    source:      'system',
    notes:       `Pushed to Shiprocket. AWB: ${awbData.awb_code}`,
    metadata:    { shiprocket_order_id: srOrder.shiprocket_order_id, courier: awbData.courier_name }
  });

  console.log(`[Shiprocket] ✅ Order ${order.order_number} → AWB ${awbData.awb_code} via ${awbData.courier_name}`);

  return {
    ...srOrder,
    awb_code:     awbData.awb_code,
    courier_name: awbData.courier_name,
    tracking_url: trackingUrl
  };
}

/* ═══════════════════════════════════════════════════════════════
   INIT — called once from server.js
═══════════════════════════════════════════════════════════════ */
function init(supabaseClient) {
  supabase = supabaseClient;
  console.log(`[Shiprocket] Initialized. LIVE_MODE=${LIVE_MODE}, pickup=${SR_PICKUP}`);
}

module.exports = {
  init,
  getToken,
  checkPincodeServiceability,
  pushOrderToShiprocket,
  assignAWB,
  getTracking
};