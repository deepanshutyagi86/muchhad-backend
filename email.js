/* ══════════════════════════════════════════════════════════════════════
   email.js — Transactional email via Brevo (formerly Sendinblue)
   ──────────────────────────────────────────────────────────────────────
   Why Brevo:
     • Free tier: 300 emails/day (way more than you need at launch)
     • Reliable transactional API
     • Sender domain verification supported
     • No setup complexity — just HTTPS POST

   Required env vars in your .env:
     BREVO_API_KEY=xkeysib-xxxxx...               (from Brevo dashboard)
     BREVO_SENDER_EMAIL=hello@muchhadeats.in     (must be verified in Brevo)
     BREVO_SENDER_NAME=Muchhad Eats              (display name)
     SITE_BASE_URL=https://muchhadeats.in        (used for links in email)

   Public API:
     sendOrderConfirmation({ supabase, orderId })
       → idempotent (checks confirmation_email_sent_at first)
       → returns { sent: bool, reason: string }
       → never throws — failure is logged, not thrown
══════════════════════════════════════════════════════════════════════ */

const BREVO_API_URL = 'https://api.brevo.com/v3/smtp/email';

const BREVO_API_KEY      = process.env.BREVO_API_KEY      || '';
const BREVO_SENDER_EMAIL = process.env.BREVO_SENDER_EMAIL || 'hello@muchhadeats.in';
const BREVO_SENDER_NAME  = process.env.BREVO_SENDER_NAME  || 'Muchhad Eats';
const SITE_BASE_URL      = process.env.SITE_BASE_URL      || 'https://muchhadeats.in';

/* ── INR formatter ─────────────────────────────────────────────────── */
function fmtINR(n) {
  const num = Number(n) || 0;
  return '₹' + num.toLocaleString('en-IN', { maximumFractionDigits: 0 });
}

/* ── Date formatter (24 Apr 2026, 11:18 am) ────────────────────────── */
function fmtDate(iso) {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    return d.toLocaleString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: 'numeric', minute: '2-digit', hour12: true,
      timeZone: 'Asia/Kolkata'
    });
  } catch (e) { return iso; }
}

/* ── Order confirmation HTML template ──────────────────────────────────
   Email-safe HTML. Tested in Gmail / Outlook / Apple Mail.
   Inline styles only. Tables for layout. No external CSS, no JS.
*/
function buildOrderEmailHTML(order, items) {
  const orderUrl = `${SITE_BASE_URL}/account/orders.html`;

  const itemRows = items.map(it => {
    const sizeText = it.size ? ` · ${escapeHtml(it.size)}` : '';
    return `
      <tr>
        <td style="padding:12px 0;border-bottom:1px solid #e8e1d0;font-family:Georgia,serif;font-size:14px;color:#3d2c1a;">
          <strong>${escapeHtml(it.product_name || 'Item')}</strong><span style="color:#7a6a55;">${sizeText}</span>
          <div style="color:#7a6a55;font-size:12px;margin-top:2px;">Qty: ${it.quantity}</div>
        </td>
        <td style="padding:12px 0;border-bottom:1px solid #e8e1d0;text-align:right;font-family:Georgia,serif;font-size:14px;color:#3d2c1a;white-space:nowrap;">
          ${fmtINR(it.line_total)}
        </td>
      </tr>`;
  }).join('');

  const couponRow = order.coupon_code && Number(order.discount_amount) > 0 ? `
    <tr>
      <td style="padding:4px 0;font-family:Georgia,serif;font-size:13px;color:#7a6a55;">
        Discount (<span style="font-family:monospace;">${escapeHtml(order.coupon_code)}</span>)
      </td>
      <td style="padding:4px 0;text-align:right;font-family:Georgia,serif;font-size:13px;color:#3d8a3d;white-space:nowrap;">
        − ${fmtINR(order.discount_amount)}
      </td>
    </tr>` : '';

  const shippingText = Number(order.shipping_fee) > 0 ? fmtINR(order.shipping_fee) : 'FREE';

  // Address block
  const addr = [
    order.shipping_address,
    order.shipping_city,
    order.shipping_state,
    order.shipping_pincode
  ].filter(Boolean).join(', ');

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/></head>
<body style="margin:0;padding:0;background:#f5ecd9;font-family:Georgia,serif;color:#3d2c1a;">
  <div style="display:none;max-height:0;overflow:hidden;">Order ${escapeHtml(order.order_number)} confirmed · ${fmtINR(order.total_amount)} · We'll ship soon!</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f5ecd9;">
    <tr><td align="center" style="padding:24px 12px;">
      <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:#fbf6e8;border:1px solid #e8d8a8;">

        <!-- HEADER -->
        <tr><td style="padding:30px 32px 20px;text-align:center;border-bottom:1px solid #e8d8a8;">
          <div style="font-family:Georgia,serif;font-size:28px;font-weight:bold;letter-spacing:2px;color:#3d2c1a;">MUCHHAD EATS</div>
          <div style="font-size:11px;color:#7a6a55;margin-top:4px;letter-spacing:3px;text-transform:uppercase;">Slow-Baked. Honest. Made in Delhi.</div>
        </td></tr>

        <!-- HERO -->
        <tr><td style="padding:32px 32px 8px;text-align:center;">
          <div style="font-size:14px;color:#7a6a55;letter-spacing:2px;text-transform:uppercase;">Order Confirmed</div>
          <div style="font-size:24px;font-weight:bold;color:#3d2c1a;margin-top:8px;">Thank you, ${escapeHtml(order.customer_name || 'friend')}!</div>
          <div style="font-size:14px;color:#7a6a55;margin-top:12px;line-height:1.5;">
            We received your order — we're getting it ready with care.<br/>
            You'll get another email when it ships.
          </div>
        </td></tr>

        <!-- ORDER META -->
        <tr><td style="padding:24px 32px 0;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e8d8a8;background:#fdfaee;">
            <tr>
              <td style="padding:16px;font-size:12px;color:#7a6a55;text-transform:uppercase;letter-spacing:1px;">Order number</td>
              <td style="padding:16px;text-align:right;font-family:monospace;font-size:14px;font-weight:bold;color:#3d2c1a;">${escapeHtml(order.order_number)}</td>
            </tr>
            <tr>
              <td style="padding:0 16px 16px;font-size:12px;color:#7a6a55;text-transform:uppercase;letter-spacing:1px;">Placed on</td>
              <td style="padding:0 16px 16px;text-align:right;font-size:13px;color:#3d2c1a;">${fmtDate(order.created_at)}</td>
            </tr>
          </table>
        </td></tr>

        <!-- ITEMS -->
        <tr><td style="padding:24px 32px 0;">
          <div style="font-size:14px;font-weight:bold;color:#3d2c1a;border-bottom:2px solid #3d2c1a;padding-bottom:8px;margin-bottom:8px;letter-spacing:1px;text-transform:uppercase;">Your order</div>
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
            ${itemRows}
          </table>
        </td></tr>

        <!-- TOTALS -->
        <tr><td style="padding:18px 32px 0;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="padding:4px 0;font-size:13px;color:#7a6a55;">Subtotal</td>
              <td style="padding:4px 0;text-align:right;font-size:13px;color:#3d2c1a;">${fmtINR(order.subtotal)}</td>
            </tr>
            <tr>
              <td style="padding:4px 0;font-size:13px;color:#7a6a55;">Shipping</td>
              <td style="padding:4px 0;text-align:right;font-size:13px;color:#3d2c1a;">${shippingText}</td>
            </tr>
            ${couponRow}
            <tr><td colspan="2" style="border-top:2px solid #3d2c1a;padding-top:8px;"></td></tr>
            <tr>
              <td style="padding:4px 0;font-size:16px;font-weight:bold;color:#3d2c1a;">Total paid</td>
              <td style="padding:4px 0;text-align:right;font-size:18px;font-weight:bold;color:#3d2c1a;">${fmtINR(order.total_amount)}</td>
            </tr>
          </table>
        </td></tr>

        <!-- SHIPPING ADDRESS -->
        <tr><td style="padding:24px 32px 0;">
          <div style="font-size:11px;color:#7a6a55;text-transform:uppercase;letter-spacing:2px;margin-bottom:6px;">Shipping to</div>
          <div style="font-size:13px;color:#3d2c1a;line-height:1.6;">
            <strong>${escapeHtml(order.customer_name || '')}</strong><br/>
            ${escapeHtml(addr || '')}<br/>
            ${escapeHtml(order.customer_phone || '')}
          </div>
        </td></tr>

        <!-- CTA -->
        <tr><td style="padding:32px 32px 16px;text-align:center;">
          <a href="${orderUrl}" style="display:inline-block;background:#3d2c1a;color:#fbf6e8;padding:14px 32px;text-decoration:none;font-weight:bold;font-size:13px;letter-spacing:2px;text-transform:uppercase;">Track your order</a>
        </td></tr>

        <!-- WHAT'S NEXT -->
        <tr><td style="padding:8px 32px 32px;">
          <div style="background:#fdfaee;border:1px solid #e8d8a8;padding:18px;font-size:13px;color:#3d2c1a;line-height:1.7;">
            <div style="font-weight:bold;margin-bottom:8px;letter-spacing:1px;text-transform:uppercase;font-size:11px;color:#7a6a55;">What's next</div>
            We bake your order fresh and pack it up. Once shipped, you'll get a tracking link by email and SMS.<br/>
            <span style="color:#7a6a55;">Typical dispatch: within 24 hours, Mon–Sat.</span>
          </div>
        </td></tr>

        <!-- FOOTER -->
        <tr><td style="padding:24px 32px;text-align:center;font-size:11px;color:#7a6a55;border-top:1px solid #e8d8a8;line-height:1.7;">
          Questions? Reply to this email or write to <a href="mailto:hello@muchhadeats.in" style="color:#3d2c1a;">hello@muchhadeats.in</a><br/>
          <a href="${SITE_BASE_URL}" style="color:#7a6a55;text-decoration:underline;">muchhadeats.in</a> · Made in Delhi
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

/* ── Plain-text fallback (for email clients that don't render HTML) ─── */
function buildOrderEmailText(order, items) {
  const lines = [];
  lines.push(`MUCHHAD EATS — Order Confirmed`);
  lines.push(`================================`);
  lines.push('');
  lines.push(`Hi ${order.customer_name || 'there'},`);
  lines.push('');
  lines.push(`Thanks for your order! Here's a recap:`);
  lines.push('');
  lines.push(`Order: ${order.order_number}`);
  lines.push(`Placed: ${fmtDate(order.created_at)}`);
  lines.push('');
  lines.push(`ITEMS`);
  items.forEach(it => {
    lines.push(`  • ${it.product_name}${it.size ? ' (' + it.size + ')' : ''} × ${it.quantity} — ${fmtINR(it.line_total)}`);
  });
  lines.push('');
  lines.push(`Subtotal: ${fmtINR(order.subtotal)}`);
  lines.push(`Shipping: ${Number(order.shipping_fee) > 0 ? fmtINR(order.shipping_fee) : 'FREE'}`);
  if (order.coupon_code && Number(order.discount_amount) > 0) {
    lines.push(`Discount (${order.coupon_code}): -${fmtINR(order.discount_amount)}`);
  }
  lines.push(`TOTAL PAID: ${fmtINR(order.total_amount)}`);
  lines.push('');
  lines.push(`Shipping to:`);
  lines.push(`  ${order.customer_name}`);
  lines.push(`  ${[order.shipping_address, order.shipping_city, order.shipping_state, order.shipping_pincode].filter(Boolean).join(', ')}`);
  lines.push(`  ${order.customer_phone}`);
  lines.push('');
  lines.push(`Track your order at: ${SITE_BASE_URL}/account/orders.html`);
  lines.push('');
  lines.push(`Questions? Reply to this email or write to hello@muchhadeats.in`);
  lines.push(`— Team Muchhad Eats`);
  return lines.join('\n');
}

/* ── HTML escape ─────────────────────────────────────────────────────── */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/* ── Low-level Brevo HTTP call ───────────────────────────────────────── */
async function sendViaBrevo({ to, subject, htmlContent, textContent, replyTo }) {
  if (!BREVO_API_KEY) {
    throw new Error('BREVO_API_KEY not configured');
  }

  const payload = {
    sender: { email: BREVO_SENDER_EMAIL, name: BREVO_SENDER_NAME },
    to: [{ email: to.email, name: to.name || undefined }],
    subject,
    htmlContent,
    textContent
  };
  if (replyTo) payload.replyTo = { email: replyTo };

  const res = await fetch(BREVO_API_URL, {
    method: 'POST',
    headers: {
      'api-key': BREVO_API_KEY,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw new Error(`Brevo ${res.status}: ${txt.slice(0, 200)}`);
  }

  const data = await res.json().catch(() => ({}));
  return data;  // { messageId: '...' }
}

/* ══════════════════════════════════════════════════════════════════════
   PUBLIC API: sendOrderConfirmation
   Idempotent: checks orders.confirmation_email_sent_at first.
   Never throws — always returns { sent, reason }.
══════════════════════════════════════════════════════════════════════ */
async function sendOrderConfirmation({ supabase, orderId }) {
  try {
    if (!BREVO_API_KEY) {
      return { sent: false, reason: 'BREVO_API_KEY not configured (skipping)' };
    }

    // Fetch order + items
    const { data: order, error: oErr } = await supabase
      .from('orders')
      .select('*')
      .eq('id', orderId)
      .single();
    if (oErr || !order) return { sent: false, reason: `Order not found: ${oErr?.message}` };

    // Idempotency check
    if (order.confirmation_email_sent_at) {
      return { sent: false, reason: 'Already sent at ' + order.confirmation_email_sent_at };
    }

    // No customer email = nothing to send (guests with phone-only orders)
    const recipient = order.customer_email;
    if (!recipient) {
      return { sent: false, reason: 'No customer email on order' };
    }

    const { data: items, error: iErr } = await supabase
      .from('order_items')
      .select('*')
      .eq('order_id', orderId);
    if (iErr) return { sent: false, reason: `Items fetch failed: ${iErr.message}` };

    const html = buildOrderEmailHTML(order, items || []);
    const text = buildOrderEmailText(order, items || []);
    const subject = `Order confirmed · ${order.order_number} · Muchhad Eats`;

    await sendViaBrevo({
      to:      { email: recipient, name: order.customer_name || undefined },
      subject,
      htmlContent: html,
      textContent: text,
      replyTo: 'hello@muchhadeats.in'
    });

    // Mark email sent (best effort)
    await supabase
      .from('orders')
      .update({ confirmation_email_sent_at: new Date().toISOString() })
      .eq('id', orderId);

    return { sent: true, reason: 'OK' };
  } catch (err) {
    console.error('[email] sendOrderConfirmation failed:', err.message);
    return { sent: false, reason: err.message };
  }
}

module.exports = { sendOrderConfirmation };