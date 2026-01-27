import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import Stripe from "stripe";
import { createClient } from "@supabase/supabase-js";
import rateLimit from "express-rate-limit";
import crypto from "crypto";

dotenv.config();
console.log("ENV CHECK:", {
  stripe: !!process.env.STRIPE_SECRET_KEY,
  supabase: !!process.env.SUPABASE_URL,
});


/* ------------------ Config ------------------ */
const ALLOWED_ORIGINS = new Set([
  "https://www.crcakesandbakes.com",
  "https://crcakesandbakes.com",
]);

const app = express();
app.disable("x-powered-by");

/* ------------------ CORS (locked) ------------------ */
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // allow no-Origin (curl, server-to-server)
      if (ALLOWED_ORIGINS.has(origin)) return cb(null, true);
      return cb(new Error("CORS: Origin not allowed"), false);
    },
    methods: ["POST", "GET", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Stripe-Signature"],
  })
);

/* ------------------ Stripe + Supabase ------------------ */
if (!process.env.STRIPE_SECRET_KEY) throw new Error("Missing STRIPE_SECRET_KEY");
if (!process.env.SUPABASE_URL) throw new Error("Missing SUPABASE_URL");
if (!process.env.SUPABASE_SERVICE_ROLE_KEY) throw new Error("Missing SUPABASE_SERVICE_ROLE_KEY");
if (!process.env.SITE_URL) throw new Error("Missing SITE_URL");



const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);


/* ------------------ Helpers ------------------ */
function clampString(s, max) {
  const v = String(s ?? "").trim();
  return v.length > max ? v.slice(0, max) : v;
}

function isValidDeliveryMethod(m) {
  return m === "collection" || m === "delivery";
}

function isValidDateYYYYMMDD(s) {
  return typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s);
}

function isAtLeastDaysAhead(dateStr, days) {
  const chosen = new Date(`${dateStr}T00:00:00`);
  if (Number.isNaN(chosen.getTime())) return false;

  const min = new Date();
  min.setHours(0, 0, 0, 0);
  min.setDate(min.getDate() + days);

  return chosen >= min;
}

function isUUID(id) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
}

// 32 hex chars (16 bytes) is plenty; you can bump to 32 bytes if you want
function generatePublicToken() {
  return crypto.randomBytes(16).toString("hex");
}

/* ------------------ Stripe Webhook (Step 4)
   IMPORTANT: express.raw() and registered BEFORE express.json()
--------------------------------------------------------------- */
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

app.post(
  "/stripe-webhook",
  webhookLimiter,
  express.raw({ type: "application/json" }),
  async (req, res) => {
    let event;

    try {
      const sig = req.headers["stripe-signature"];
      if (!sig) return res.status(400).send("Missing stripe-signature header");
      if (!process.env.STRIPE_WEBHOOK_SECRET) return res.status(500).send("Webhook not configured");

      event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
      console.log("✅ Stripe webhook:", event.type, event.id);
    } catch (err) {
      console.error("❌ Webhook signature verification failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        const orderId = session.client_reference_id || session.metadata?.order_id;
        if (!orderId) return res.json({ received: true });

        if (session.payment_status === "paid") {
          const { error } = await supabase
            .from("orders")
            .update({
              status: "paid",
              stripe_payment_intent_id: session.payment_intent || null,
            })
            .eq("id", orderId)
            .eq("status", "pending");

          if (error) console.error("❌ Supabase update error (completed):", error);
        }
      }

      if (event.type === "checkout.session.expired") {
        const session = event.data.object;
        const orderId = session.client_reference_id || session.metadata?.order_id;

        if (orderId) {
          const { error } = await supabase
            .from("orders")
            .update({ status: "cancelled" })
            .eq("id", orderId)
            .eq("status", "pending");

          if (error) console.error("❌ Supabase update error (expired):", error);
        }
      }

      return res.json({ received: true });
    } catch (err) {
      console.error("❌ Webhook handler error:", err);
      return res.status(500).send("Webhook handler failed");
    }
  }
);

/* ------------------ JSON parser (AFTER webhook) ------------------ */
app.use(express.json({ limit: "50kb" }));

/* ------------------ Rate limit (checkout) ------------------ */
const checkoutLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

/* ------------------ Token-protected order status ------------------
   Client calls: GET /order/<id>?token=<public_token>
--------------------------------------------------------------- */
app.get("/order/:id", async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();
    const token = clampString(req.query.token, 128);

    if (!isUUID(id)) return res.status(400).json({ error: "Invalid order id" });
    if (!token) return res.status(400).json({ error: "Missing token" });

    // Query by both id and token — if mismatch, returns 404
    const { data, error } = await supabase
      .from("orders")
      .select("id,status,subtotal,delivery_fee,total,delivery_method,delivery_date,created_at")
      .eq("id", id)
      .eq("public_token", token)
      .single();

    if (error || !data) return res.status(404).json({ error: "Order not found" });

    return res.json(data);
  } catch (err) {
    console.error("❌ order lookup error:", err);
    return res.status(500).json({ error: "Unable to fetch order" });
  }
});

/* ------------------ Checkout route ------------------ */
app.post("/create-checkout-session", checkoutLimiter, async (req, res) => {
  try {
    const { items, delivery, delivery_date } = req.body;

    // ---- validate request ----
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Invalid items array" });
    }

    if (!delivery_date) {
      return res.status(400).json({ error: "Delivery/collection date is required" });
    }

    if (!isValidDateYYYYMMDD(delivery_date)) {
      return res.status(400).json({ error: "Invalid delivery_date format (YYYY-MM-DD)" });
    }

    if (!isAtLeastDaysAhead(delivery_date, 2)) {
      return res.status(400).json({ error: "Delivery date must be at least 2 days ahead" });
    }

    const delivery_method = delivery?.method || "collection";
    if (!isValidDeliveryMethod(delivery_method)) {
      return res.status(400).json({ error: "Invalid delivery method" });
    }

    const isDelivery = delivery_method === "delivery";
    const postcode = clampString(delivery?.postcode, 12).toUpperCase();
    if (isDelivery && !postcode) {
      return res.status(400).json({ error: "Postcode required for delivery" });
    }

    // ---- sanitize items ----
    const cleanedItems = items.map((it) => ({
      product_id: clampString(it.product_id, 80),
      quantity: Number(it.quantity),
      flavour: clampString(it.flavour, 60),
      notes: clampString(it.notes, 200),
    }));

    for (const it of cleanedItems) {
      if (!it.product_id) return res.status(400).json({ error: "Missing product_id" });
      if (!Number.isInteger(it.quantity) || it.quantity < 1 || it.quantity > 20) {
        return res.status(400).json({ error: "Invalid quantity" });
      }
    }

    // ---- fetch authoritative products/prices ----
    const ids = [...new Set(cleanedItems.map((i) => i.product_id))];

    const { data: products, error: prodErr } = await supabase
      .from("products")
      .select("id, name, price")
      .in("id", ids);

    if (prodErr) {
      console.error("❌ Supabase product lookup error:", prodErr);
      return res.status(500).json({ error: "Unable to fetch products" });
    }

    const productMap = new Map(products.map((p) => [String(p.id), p]));

    // ---- compute totals server-side ----
    let subtotal = 0;
    for (const it of cleanedItems) {
      const p = productMap.get(it.product_id);
      if (!p) return res.status(400).json({ error: "Invalid product in cart" });

      const price = Number(p.price);
      if (!Number.isFinite(price) || price < 0) {
        return res.status(500).json({ error: "Invalid product price configuration" });
      }

      subtotal += price * it.quantity;
    }

    const deliveryFee = isDelivery && subtotal < 35 ? 3 : 0;
    const total = subtotal + deliveryFee;

    // ---- generate token for public status polling ----
    const public_token = generatePublicToken();

    // ---- create order (pending) ----
    const { data: order, error: orderError } = await supabase
      .from("orders")
      .insert({
        items: cleanedItems,
        delivery_method,
        postcode,
        delivery_date,
        delivery_fee: Math.round(deliveryFee * 100),
        subtotal: Math.round(subtotal * 100),
        total: Math.round(total * 100),
        status: "pending",
        public_token,
      })
      .select()
      .single();

    if (orderError) {
      console.error("❌ Supabase insert error:", orderError);
      return res.status(500).json({ error: "Unable to create order" });
    }

    // ---- Stripe line items ----
    const line_items = cleanedItems.map((it) => {
      const p = productMap.get(it.product_id);
      return {
        price_data: {
          currency: "gbp",
          product_data: {
            name: p.name,
            description: `Topping: ${it.flavour || "None"} | Notes: ${it.notes || "None"}`,
          },
          unit_amount: Math.round(Number(p.price) * 100),
        },
        quantity: it.quantity,
      };
    });

    if (deliveryFee > 0) {
      line_items.push({
        price_data: {
          currency: "gbp",
          product_data: { name: "Delivery Fee" },
          unit_amount: Math.round(deliveryFee * 100),
        },
        quantity: 1,
      });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items,
      success_url: `${process.env.SITE_URL}/success.html?orderId=${order.id}`,
      cancel_url: `${process.env.SITE_URL}/cancel.html`,
      client_reference_id: String(order.id),

      ...(isDelivery
        ? {
            shipping_address_collection: { allowed_countries: ["GB"] },
            phone_number_collection: { enabled: true },
          }
        : {}),

      metadata: {
        order_id: String(order.id),
        delivery_date,
        delivery_method,
        postcode,
      },

      payment_intent_data: {
        metadata: {
          order_id: String(order.id),
          delivery_date,
          delivery_method,
          postcode,
        },
      },
    });

    // store stripe session id
    await supabase
      .from("orders")
      .update({ stripe_session_id: session.id })
      .eq("id", order.id);

    // Return both orderId + token for success page polling
    return res.json({ id: session.id, orderId: order.id, token: public_token });
  } catch (err) {
    console.error("❌ Stripe checkout error:", err);
    return res.status(500).json({ error: "Unable to create checkout session" });
  }
});

/* ------------------ Start ------------------ */
const port = process.env.PORT || 5000;
app.listen(port, () => console.log(`✅ Server running on port ${port}`));




