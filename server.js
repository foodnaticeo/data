require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

for (const name of ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'ADMIN_API_KEY', 'ALLOWED_ORIGINS']) {
  if (!process.env[name]) throw new Error(`Missing Render environment variable: ${name}`);
}
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
const app = express();
const TABLE = 'resturnatappplication';
const BUCKET = 'restaurant-applications';
const allowedOrigins = process.env.ALLOWED_ORIGINS.split(',').map(x => x.trim()).filter(Boolean);
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({ origin(origin, cb) { cb(null, !origin || allowedOrigins.includes(origin)); } }));
app.use(express.json({ limit: '100kb' }));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, limit: 50, standardHeaders: 'draft-7', legacyHeaders: false }));

function adminOnly(req, res, next) {
  const token = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  const a = Buffer.from(token);
  const b = Buffer.from(process.env.ADMIN_API_KEY);
  if (!a.length || a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ success: false, message: 'Unauthorized' });
  next();
}
function string(value, max = 300) { return typeof value === 'string' ? value.trim().slice(0, max) : null; }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {}; }
function validId(value) { return /^\d+$/.test(value); }
function fail(res, error, message = 'Database operation failed') { console.error(message, error); return res.status(500).json({ success: false, message }); }

app.get('/', (_req, res) => res.json({ success: true, message: 'Foodnati Restaurant API running' }));

app.post('/api/restaurant/apply', async (req, res) => {
  const b = req.body || {};
  const restaurant_name = string(b.restaurant_name, 200);
  const mobile_number = string(b.mobile_number, 20);
  if (!restaurant_name || !/^[+]?[0-9 -]{10,20}$/.test(mobile_number || '')) return res.status(400).json({ success: false, message: 'Valid restaurant name and mobile number required' });
  const payload = {
    restaurant_name, mobile_number,
    owner_name: string(b.owner_name, 200),
    food_menu_images: Array.isArray(b.food_menu_images) ? b.food_menu_images.filter(x => typeof x === 'string').slice(0, 20) : [],
    fssai_number: string(b.fssai_number, 30),
    location: object(b.location),
    bank_account: object(b.bank_account),
    pan_card: object(b.pan_card),
    gst_number: string(b.gst_number, 30),
    gst_certificate_url: string(b.gst_certificate_url, 1000),
    restaurant_details: object(b.restaurant_details),
    application_status: 'pending'
  };
  const { data, error } = await supabase.from(TABLE).insert(payload).select('id,restaurant_name,application_status,created_at').single();
  if (error) return fail(res, error, 'Application submission failed');
  return res.status(201).json({ success: true, application: data });
});

app.get('/api/restaurant/applications', adminOnly, async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const { data, error, count } = await supabase.from(TABLE).select('*', { count: 'exact' }).order('created_at', { ascending: false }).range((page - 1) * limit, page * limit - 1);
  if (error) return fail(res, error);
  return res.json({ success: true, page, total: count, applications: data });
});

app.get('/api/restaurant/application/:id', adminOnly, async (req, res) => {
  if (!validId(req.params.id)) return res.status(400).json({ success: false, message: 'Invalid ID' });
  const { data, error } = await supabase.from(TABLE).select('*').eq('id', req.params.id).maybeSingle();
  if (error) return fail(res, error);
  if (!data) return res.status(404).json({ success: false, message: 'Application not found' });
  return res.json({ success: true, application: data });
});

app.patch('/api/restaurant/application/:id/status', adminOnly, async (req, res) => {
  if (!validId(req.params.id)) return res.status(400).json({ success: false, message: 'Invalid ID' });
  const status = req.body?.application_status;
  if (!['pending', 'approved', 'rejected'].includes(status)) return res.status(400).json({ success: false, message: 'Invalid status' });
  const { data, error } = await supabase.from(TABLE).update({ application_status: status, rejection_reason: status === 'rejected' ? string(req.body.rejection_reason, 500) : null, updated_at: new Date().toISOString() }).eq('id', req.params.id).select('id,application_status,updated_at').maybeSingle();
  if (error) return fail(res, error);
  if (!data) return res.status(404).json({ success: false, message: 'Application not found' });
  return res.json({ success: true, application: data });
});

const mimeToExt = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'application/pdf': 'pdf' };
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 }, fileFilter(_req, file, cb) { cb(null, Boolean(mimeToExt[file.mimetype])); } });
app.post('/api/restaurant/upload', adminOnly, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, message: 'JPEG, PNG, WEBP or PDF file required' });
  const path = `uploads/${crypto.randomUUID()}.${mimeToExt[req.file.mimetype]}`;
  const { error } = await supabase.storage.from(BUCKET).upload(path, req.file.buffer, { contentType: req.file.mimetype, upsert: false });
  if (error) return fail(res, error, 'Upload failed');
  return res.status(201).json({ success: true, path });
});
app.get('/api/restaurant/file', adminOnly, async (req, res) => {
  const path = req.query.path;
  if (typeof path !== 'string' || !/^uploads\/[a-f0-9-]+\.(jpg|png|webp|pdf)$/.test(path)) return res.status(400).json({ success: false, message: 'Invalid file path' });
  const { data, error } = await supabase.storage.from(BUCKET).createSignedUrl(path, 300);
  if (error) return fail(res, error, 'File access failed');
  return res.json({ success: true, url: data.signedUrl, expires_in: 300 });
});
app.use((err, _req, res, _next) => { console.error(err); res.status(400).json({ success: false, message: 'Invalid upload or request' }); });
const port = Number(process.env.PORT) || 3000;
app.listen(port, '0.0.0.0', () => console.log(`Foodnati API listening on ${port}`));
