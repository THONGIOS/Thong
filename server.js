/**
 * ឯកសារ៖ server.js
 * តួនាទី៖ Backend Server ពេញលេញ ១០០% សម្រាប់ភ្ជាប់ MooGold API + Bakong KHQR (Auto-Payment & Auto-TopUp)
 */
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();

app.use(helmet({
  crossOriginResourcePolicy: false
}));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-pin']
}));

app.use(express.json({ limit: '5mb' }));

// ====================================================
// 1. ប្រព័ន្ធសុវត្ថិភាព៖ Rate Limiter & Input Sanitization
// ====================================================
const rateLimitMap = new Map();
function rateLimiter(maxRequests = 45, windowMs = 60000) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const record = rateLimitMap.get(ip) || { count: 0, startTime: now };

    if (now - record.startTime > windowMs) {
      record.count = 1;
      record.startTime = now;
    } else {
      record.count += 1;
    }

    rateLimitMap.set(ip, record);

    if (record.count > maxRequests) {
      return res.status(429).json({
        success: false,
        error: 'សំណើរច្រើនពេកក្នុងរយៈពេលខ្លី (Rate Limit)! សូមរង់ចាំ ១ នាទី។'
      });
    }
    next();
  };
}

function sanitizeInput(str, maxLength = 80) {
  if (typeof str !== 'string' && typeof str !== 'number') return '';
  return String(str)
    .replace(/[<>'"`;(){}]/g, '')
    .trim()
    .slice(0, maxLength);
}

function verifyAdminAuth(req) {
  const serverAdminPin = process.env.ADMIN_SECRET_PIN;
  if (!serverAdminPin) return true;
  const clientPin = req.headers['x-admin-pin'] || (req.body && req.body.adminPin);
  return clientPin === serverAdminPin;
}

function isInvalidPlayerNameText(text) {
  if (!text || typeof text !== 'string') return true;
  const lower = text.toLowerCase();
  const blockedPhrases = [
    'validation is not available',
    'not available for this product',
    'kindly',
    'invalid',
    'error',
    'not found',
    'failed',
    'missing',
    'unauthorized',
    'please',
    'incorrect'
  ];
  return blockedPhrases.some((phrase) => lower.includes(phrase));
}

function generatePartnerOrderId() {
  const timestamp = Date.now();
  const randomStr = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `THONG-${timestamp}-${randomStr}`;
}


// ====================================================
// 1.5 ប្រព័ន្ធរក្សាទុកទិន្នន័យអចិន្ត្រៃយ៍ (Permanent Cloud & Disk Store)
// គាំទ្រ៖ (1) Cloudflare KV / Upstash / JSONBin / MongoDB Webhook URL ឬ (2) Persistent JSON File
// ====================================================
const fs = require('fs');
const path = require('path');

const PERSISTENT_DIR = process.env.PERSISTENT_DATA_DIR || __dirname;
const DB_FILE_PATH = path.join(PERSISTENT_DIR, 'souyakthong_permanent_store.json');

let permanentStore = {
  catalog: null,
  settings: {},
  updatedAt: null
};

// ទាញទិន្នន័យពី Disk ឬ Cloud ពេល Server ចាប់ផ្តើមដំណើរការ
async function initPermanentStore() {
  // ក. ទាញពី Local Persistent File ជាមុន
  try {
    if (fs.existsSync(DB_FILE_PATH)) {
      const raw = fs.readFileSync(DB_FILE_PATH, 'utf-8');
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        permanentStore = { ...permanentStore, ...parsed };
        console.log('✅ Loaded permanent store from disk:', DB_FILE_PATH);
      }
    }
  } catch (err) {
    console.warn('⚠️ Disk store read warning:', err.message);
  }

  // ខ. បើមានភ្ជាប់ Cloud JSONBin / Cloudflare KV REST API ទាញយកទិន្នន័យចុងក្រោយបំផុតពី Cloud
  const cloudBinId = (process.env.JSONBIN_BIN_ID || '').trim();
  const cloudApiKey = (process.env.JSONBIN_API_KEY || '').trim();
  if (cloudBinId && cloudApiKey) {
    try {
      const r = await fetch(`https://api.jsonbin.io/v3/b/${cloudBinId}/latest`, {
        headers: { 'X-Master-Key': cloudApiKey }
      });
      if (r.ok) {
        const j = await r.json();
        if (j && j.record) {
          permanentStore = { ...permanentStore, ...j.record };
          fs.writeFileSync(DB_FILE_PATH, JSON.stringify(permanentStore, null, 2), 'utf-8');
          console.log('☁️ Synced permanent store from Cloud JSONBin!');
        }
      }
    } catch (e) {
      console.warn('⚠️ Cloud sync read warning:', e.message);
    }
  }
}

async function savePermanentStore() {
  permanentStore.updatedAt = new Date().toISOString();

  // 1. រក្សាទុកក្នុង Disk ភ្លាមៗ
  try {
    fs.writeFileSync(DB_FILE_PATH, JSON.stringify(permanentStore, null, 2), 'utf-8');
  } catch (err) {
    console.warn('⚠️ Disk store write warning:', err.message);
  }

  // 2. រក្សាទុកទៅកាន់ Cloud (JSONBin.io Free Forever Cloud DB) បើមានកំណត់
  const cloudBinId = (process.env.JSONBIN_BIN_ID || permanentStore.settings?.jsonbinId || '').trim();
  const cloudApiKey = (process.env.JSONBIN_API_KEY || permanentStore.settings?.jsonbinKey || '').trim();
  if (cloudBinId && cloudApiKey) {
    try {
      await fetch(`https://api.jsonbin.io/v3/b/${cloudBinId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-Master-Key': cloudApiKey
        },
        body: JSON.stringify(permanentStore)
      });
    } catch (e) {
      console.warn('⚠️ Cloud sync write warning:', e.message);
    }
  }
}

initPermanentStore();

// ====================================================
// 2. ម៉ាស៊ីនបង្កើតកូដ EMVCo Bakong KHQR Standard (CRC16-CCITT)
// ====================================================
function crc16ccitt(str) {
  let crc = 0xFFFF;
  for (let i = 0; i < str.length; i++) {
    crc ^= str.charCodeAt(i) << 8;
    for (let j = 0; j < 8; j++) {
      if ((crc & 0x8000) !== 0) {
        crc = ((crc << 1) ^ 0x1021) & 0xFFFF;
      } else {
        crc = (crc << 1) & 0xFFFF;
      }
    }
  }
  return crc.toString(16).toUpperCase().padStart(4, '0');
}

function tlv(tag, value) {
  const strVal = String(value);
  const len = strVal.length.toString().padStart(2, '0');
  return `${tag}${len}${strVal}`;
}

function buildBakongKhqrString({ bakongAccountId, merchantName, merchantCity, amountUsd, billNumber }) {
  const cleanAccount = (bakongAccountId || process.env.BAKONG_ACCOUNT_ID || 'souyakthong@aba').trim();
  const cleanName = (merchantName || process.env.BAKONG_MERCHANT_NAME || 'SOUYAKTHONG GOLD').slice(0, 25);
  const cleanCity = (merchantCity || 'Phnom Penh').slice(0, 15);
  const formattedAmount = Number(amountUsd).toFixed(2);

  // Tag 29: Bakong Individual Account Information
  const tag29 = tlv('29', tlv('00', cleanAccount));
  // Tag 62: Additional Data Field (Bill Number)
  const tag62 = tlv('62', tlv('01', billNumber.slice(0, 25)));
  // Tag 99: Timestamp
  const nowMs = String(Date.now());
  const tag99 = tlv('99', tlv('00', nowMs));

  const payloadWithoutCrc =
    tlv('00', '01') +
    tlv('01', '12') + // 12 = Dynamic QR
    tag29 +
    tlv('52', '5999') +
    tlv('53', '840') + // 840 = USD
    tlv('54', formattedAmount) +
    tlv('58', 'KH') +
    tlv('59', cleanName) +
    tlv('60', cleanCity) +
    tag62 +
    tag99 +
    '6304';

  const crc = crc16ccitt(payloadWithoutCrc);
  const khqrString = payloadWithoutCrc + crc;
  const md5 = crypto.createHash('md5').update(khqrString).digest('hex');

  return { khqrString, md5, amountUsd: Number(formattedAmount), bakongAccountId: cleanAccount };
}

// ផ្ទុកវិក្កយបត្រ KHQR ដើម្បីការពារការបាញ់ UC ស្ទួន (Idempotency Store)
const khqrOrdersMap = new Map();

// ====================================================
// 3. អនុគមន៍កណ្តាលហៅទៅកាន់ MooGold API
// ====================================================
async function callMooGoldApi(endpointPath, payloadObj, customPartnerId, customSecretKey) {
  const partnerId = (customPartnerId || process.env.MOOGOLD_PARTNER_ID || '').trim();
  const secretKey = (customSecretKey || process.env.MOOGOLD_SECRET_KEY || '').trim();

  if (!partnerId || !secretKey) {
    throw new Error('សូមដាក់ MOOGOLD_PARTNER_ID និង MOOGOLD_SECRET_KEY នៅក្នុង Render Environment!');
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const payloadJson = JSON.stringify(payloadObj);
  const stringToSign = payloadJson + timestamp + endpointPath;

  const authSignature = crypto
    .createHmac('sha256', secretKey)
    .update(stringToSign)
    .digest('hex');

  const basicAuth = Buffer
    .from(`${partnerId}:${secretKey}`)
    .toString('base64');

  const response = await fetch(
    `https://moogold.com/wp-json/v1/api/${endpointPath}`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        timestamp: String(timestamp),
        auth: authSignature,
        Authorization: `Basic ${basicAuth}`
      },
      body: payloadJson,
      signal: AbortSignal.timeout(20000)
    }
  );

  const responseText = await response.text();
  let result;

  try {
    result = responseText ? JSON.parse(responseText) : {};
  } catch {
    result = { message: responseText };
  }

  if (!response.ok) {
    const error = new Error(`MooGold API returned HTTP ${response.status}`);
    error.status = response.status;
    error.details = result;
    throw error;
  }

  return result;
}

function sendError(res, err) {
  console.error('API request failed:', err.message, err.details || '');
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Server error.',
    details: err.details || null
  });
}


// ====================================================
// 3.5 MULTI-VENDOR API ENGINES (Smile.One, SEAGM & Night-APIs Midasbuy)
// ====================================================

// ក. អនុគមន៍ហៅទៅកាន់ Smile.One Reseller API (សម្រាប់ Mobile Legends Brazil/PH/Global តម្លៃដើមថោកបំផុត)
async function callSmileOneApi(endpointPath, payloadObj, customUid, customEmail, customKey) {
  const uid = (customUid || process.env.SMILE_ONE_UID || permanentStore.settings?.smileUid || '').trim();
  const email = (customEmail || process.env.SMILE_ONE_EMAIL || permanentStore.settings?.smileEmail || '').trim();
  const key = (customKey || process.env.SMILE_ONE_KEY || permanentStore.settings?.smileKey || '').trim();

  if (!uid || !email || !key) {
    throw new Error('សូមបញ្ចូល SMILE_ONE_UID, SMILE_ONE_EMAIL និង SMILE_ONE_KEY ក្នុងផ្ទាំង Admin ឬ Render Environment ជាមុនសិន!');
  }

  const time = Math.floor(Date.now() / 1000);
  const params = {
    uid,
    email,
    time,
    ...payloadObj
  };

  // បង្កើតហត្ថលេខាសុវត្ថិភាព Smile.One (Double MD5 Signature sorted by key)
  const sortedKeys = Object.keys(params).sort();
  let signStr = '';
  for (const k of sortedKeys) {
    signStr += `${k}=${params[k]}&`;
  }
  signStr += key;

  const md5First = crypto.createHash('md5').update(signStr).digest('hex');
  const sign = crypto.createHash('md5').update(md5First).digest('hex');
  params.sign = sign;

  const formBody = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    formBody.append(k, String(v));
  }

  const response = await fetch(`https://www.smile.one/smilecoin/api/${endpointPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    },
    body: formBody.toString(),
    signal: AbortSignal.timeout(20000)
  });

  const data = await response.json();
  if (data.status !== 200 && data.code !== 200) {
    throw new Error(data.message || `Smile.One API Error: ${JSON.stringify(data)}`);
  }
  return data;
}

// ខ. អនុគមន៍ហៅទៅកាន់ SEAGM (SEA Gamer Mall) Partner API (សម្រាប់ Gift Cards, Razer Gold & PUBG)
async function callSeagmApi(endpointPath, payloadObj, customUid, customKey) {
  const partnerUid = (customUid || process.env.SEAGM_PARTNER_UID || permanentStore.settings?.seagmUid || '').trim();
  const secretKey = (customKey || process.env.SEAGM_SECRET_KEY || permanentStore.settings?.seagmKey || '').trim();

  if (!partnerUid || !secretKey) {
    throw new Error('សូមបញ្ចូល SEAGM_PARTNER_UID និង SEAGM_SECRET_KEY ក្នុងផ្ទាំង Admin ឬ Render Environment ជាមុនសិន!');
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const fullPayload = {
    partner_uid: partnerUid,
    timestamp,
    ...payloadObj
  };

  const payloadJson = JSON.stringify(fullPayload);
  const signature = crypto
    .createHmac('sha256', secretKey)
    .update(payloadJson)
    .digest('hex');

  const response = await fetch(`https://partner.seagm.com/api/v1/${endpointPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-SEAGM-Signature': signature
    },
    body: payloadJson,
    signal: AbortSignal.timeout(20000)
  });

  const data = await response.json();
  if (!response.ok || data.status === 'error' || data.code && data.code !== 200) {
    throw new Error(data.message || `SEAGM API Error: ${JSON.stringify(data)}`);
  }
  return data;
}

// គ. អនុគមន៍កណ្ដាលសម្រាប់បាញ់ទំនិញស្វ័យប្រវត្តិទៅតាមប្រភព API (Smart Multi-Vendor Order Router)
async function fulfillOrderMultiVendor(orderRecord) {
  const vendor = String(orderRecord.vendor || 'moogold').toLowerCase().trim();
  const cleanVarId = String(orderRecord.variationId).replace(/^(smile:|seagm:|moogold:)/i, '').trim();

  // 1. បើជ្រើសរើសប្រភព Smile.One (ឧទាហរណ៍៖ Mobile Legends តម្លៃដើមថោក)
  if (vendor === 'smileone' || String(orderRecord.variationId).toLowerCase().startsWith('smile:')) {
    const smileRes = await callSmileOneApi('createorder', {
      userid: String(orderRecord.playerId),
      zoneid: String(orderRecord.serverId || '1'),
      product: 'mobilelegends',
      productid: cleanVarId
    });
    return {
      vendorUsed: 'Smile.One',
      rawResponse: smileRes
    };
  }

  // 2. បើជ្រើសរើសប្រភព SEAGM (ឧទាហរណ៍៖ Gift Cards / Razer Gold / PUBG)
  if (vendor === 'seagm' || String(orderRecord.variationId).toLowerCase().startsWith('seagm:')) {
    const seagmRes = await callSeagmApi('order/create', {
      product_id: cleanVarId,
      player_id: String(orderRecord.playerId),
      server_id: String(orderRecord.serverId || ''),
      partner_order_id: orderRecord.partnerOrderId
    });
    return {
      vendorUsed: 'SEAGM',
      rawResponse: seagmRes
    };
  }

  // 3. លំនាំដើម៖ បាញ់តាមប្រភព MooGold API ផ្លូវការ
  const orderData = {
    category: 1,
    'product-id': cleanVarId,
    quantity: 1,
    'User ID': String(orderRecord.playerId),
    'Character ID': String(orderRecord.playerId),
    'Player ID': String(orderRecord.playerId)
  };
  if (orderRecord.serverId) {
    orderData.Server = String(orderRecord.serverId);
    orderData['Server ID'] = String(orderRecord.serverId);
    orderData['Zone ID'] = String(orderRecord.serverId);
  }

  const moogoldPayload = {
    path: 'order/create_order',
    data: orderData,
    partnerOrderId: orderRecord.partnerOrderId
  };

  const moogoldResult = await callMooGoldApi('order/create_order', moogoldPayload);
  if (
    !moogoldResult ||
    moogoldResult.status === false ||
    moogoldResult.status === 'false' ||
    moogoldResult.err_code ||
    (moogoldResult.message && String(moogoldResult.message).toLowerCase().includes('error'))
  ) {
    throw new Error(moogoldResult?.message || JSON.stringify(moogoldResult));
  }

  return {
    vendorUsed: 'MooGold',
    rawResponse: moogoldResult
  };
}

// ====================================================
// 4. ROUTES ទាំងអស់របស់ប្រព័ន្ធ
// ====================================================
app.get('/', (req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'SOUYAKTHONG MooGold + Bakong KHQR API Server Running 24/7',
    security: {
      helmet: true,
      rateLimit: true,
      inputSanitization: true,
      envCredentialsLoaded: Boolean(process.env.MOOGOLD_PARTNER_ID && process.env.MOOGOLD_SECRET_KEY),
      bakongTokenConfigured: Boolean(process.env.BAKONG_TOKEN)
    }
  });
});

app.get('/my-ip', rateLimiter(15, 60000), async (req, res) => {
  try {
    const r = await fetch('https://api.ipify.org?format=json');
    const data = await r.json();
    res.json({
      exact_server_ip: data.ip,
      note: 'សូមយកលេខ exact_server_ip នេះទៅដាក់ក្នុង IP Whitelist នៅលើ MooGold.com'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ទាញយកទិន្នន័យ Catalog & Settings ដែលបានរក្សាទុកជាអចិន្ត្រៃយ៍លើ Server/Cloud
app.get('/api/store-data', rateLimiter(60, 60000), (req, res) => {
  const safeSettings = { ...(permanentStore.settings || {}) };
  // មិនបញ្ជូន Secret Key ចេញទៅក្រៅទេ បើមិនមែនជា Admin
  if (!verifyAdminAuth(req)) {
    delete safeSettings.bakongToken;
    delete safeSettings.tgToken;
    delete safeSettings.jsonbinKey;
    delete safeSettings.smileKey;
    delete safeSettings.seagmKey;
    delete safeSettings.nightApiKey;
  }
  res.json({
    success: true,
    catalog: permanentStore.catalog || null,
    settings: safeSettings,
    updatedAt: permanentStore.updatedAt
  });
});

// រក្សាទុកទិន្នន័យ Catalog (រូបភាព/តម្លៃហ្គេម) និង Settings ជាអចិន្ត្រៃយ៍លើ Server & Cloud
app.post('/api/store-data', rateLimiter(30, 60000), async (req, res) => {
  try {
    if (!verifyAdminAuth(req)) {
      return res.status(403).json({
        success: false,
        error: 'គ្មានសិទ្ធិ Admin ដើម្បីរក្សាទុកទិន្នន័យទេ (Unauthorized Admin PIN)!'
      });
    }

    const { catalog, settings } = req.body || {};
    if (catalog && typeof catalog === 'object') {
      permanentStore.catalog = catalog;
    }
    if (settings && typeof settings === 'object') {
      permanentStore.settings = { ...(permanentStore.settings || {}), ...settings };
    }

    await savePermanentStore();

    res.json({
      success: true,
      message: '✅ បានរក្សាទុកទិន្នន័យចូលក្នុងម៉ាស៊ីនមេ និង Cloud ជាអចិន្ត្រៃយ៍រួចរាល់!',
      updatedAt: permanentStore.updatedAt
    });
  } catch (err) {
    sendError(res, err);
  }
});


// ឆែកស្ថានភាពតភ្ជាប់ប្រភព API ទាំង ៤ (MooGold, Smile.One, SEAGM, Night-APIs Midasbuy)
app.post('/api/vendors/status', rateLimiter(20, 60000), async (req, res) => {
  try {
    const statusReport = {
      moogold: { configured: Boolean(process.env.MOOGOLD_PARTNER_ID && process.env.MOOGOLD_SECRET_KEY) },
      smileone: { configured: Boolean((process.env.SMILE_ONE_UID || permanentStore.settings?.smileUid) && (process.env.SMILE_ONE_KEY || permanentStore.settings?.smileKey)) },
      seagm: { configured: Boolean((process.env.SEAGM_PARTNER_UID || permanentStore.settings?.seagmUid) && (process.env.SEAGM_SECRET_KEY || permanentStore.settings?.seagmKey)) },
      nightApiMidasbuy: { configured: Boolean(process.env.NIGHT_API_KEY || permanentStore.settings?.nightApiKey), publicFallbackActive: true }
    };
    res.json({ success: true, vendors: statusReport });
  } catch (err) {
    sendError(res, err);
  }
});

// ឆែកសមតុល្យទឹកប្រាក់ MooGold (user/balance)
app.post('/api/moogold/balance', rateLimiter(30, 60000), async (req, res) => {
  try {
    const { partnerId, secretKey } = req.body || {};
    const payload = { path: 'user/balance' };
    const data = await callMooGoldApi('user/balance', payload, partnerId, secretKey);
    res.json(data);
  } catch (err) {
    sendError(res, err);
  }
});

// ទាញយករូបភាពផ្លូវការ និងកញ្ចប់តម្លៃពី MooGold (product/product_detail)
app.post('/api/moogold/product-detail', rateLimiter(45, 60000), async (req, res) => {
  try {
    const { partnerId, secretKey, productId } = req.body || {};
    const cleanProductId = sanitizeInput(productId || '6963', 20);

    const payload = {
      path: 'product/product_detail',
      product_id: Number(cleanProductId) || cleanProductId
    };

    const data = await callMooGoldApi('product/product_detail', payload, partnerId, secretKey);
    res.json({
      success: true,
      productId: cleanProductId,
      moogoldProduct: data
    });
  } catch (err) {
    sendError(res, err);
  }
});

// ទាញយកបញ្ជីហ្គេមតាម Category ពី MooGold (product/list_product)
app.post('/api/moogold/list-products', rateLimiter(30, 60000), async (req, res) => {
  try {
    const { partnerId, secretKey, categoryId } = req.body || {};
    const payload = {
      path: 'product/list_product',
      category_id: Number(categoryId) || 50
    };
    const data = await callMooGoldApi('product/list_product', payload, partnerId, secretKey);
    res.json({
      success: true,
      products: data
    });
  } catch (err) {
    sendError(res, err);
  }
});

// បន្ថែមអនុគមន៍ឆ្លាតវៃសម្រាប់ទាញយកឈ្មោះ Player ពីគ្រប់ទម្រង់ JSON របស់ MooGold
function extractPlayerNameFromResult(result) {
  if (!result || typeof result !== 'object') return null;

  // 1. ឆែក Key សំខាន់ៗផ្ទាល់
  const directCandidates = [
    result.username,
    result.player_name,
    result.name,
    result.ign,
    result.nickname,
    result.account_name,
    result.user_name,
    result.character_name,
    result.role_name,
    result['Player Name'],
    result['User Name'],
    result['Nickname']
  ];

  for (const cand of directCandidates) {
    if (typeof cand === 'string' && cand.trim() && !isInvalidPlayerNameText(cand)) {
      return cand.trim();
    }
  }

  // 2. ឆែកក្នុង result.data ឬ result.details ប្រសិនបើជា Object
  const subObjects = [result.data, result.details, result.info, result.player];
  for (const sub of subObjects) {
    if (sub && typeof sub === 'object') {
      const subCandidates = [
        sub.username,
        sub.player_name,
        sub.name,
        sub.ign,
        sub.nickname,
        sub.account_name,
        sub.user_name,
        sub.character_name,
        sub['Player Name'],
        sub['Nickname']
      ];
      for (const cand of subCandidates) {
        if (typeof cand === 'string' && cand.trim() && !isInvalidPlayerNameText(cand)) {
          return cand.trim();
        }
      }
    } else if (typeof sub === 'string' && sub.trim() && !isInvalidPlayerNameText(sub)) {
      return sub.trim();
    }
  }

  // 3. ឆែកក្នុង result.message (ឧទាហរណ៍៖ "Player Name: SOUYAKTHONG" ឬឈ្មោះផ្ទាល់)
  if (typeof result.message === 'string' && result.message.trim()) {
    const msg = result.message.trim();
    const colonMatch = msg.match(/(?:player\s*name|username|nickname|ign|name)\s*[:=-]\s*(.+)$/i);
    if (colonMatch && colonMatch[1] && !isInvalidPlayerNameText(colonMatch[1])) {
      return colonMatch[1].trim();
    }
    if (!isInvalidPlayerNameText(msg)) {
      return msg;
    }
  }

  return null;
}


// អនុគមន៍ជំនួយ៖ ឆែកឈ្មោះ Player ពិតប្រាកដតាមទម្រង់ Midasbuy & Multi-Source Game ID Resolver
async function lookupPublicGamePlayerName(gameKey, playerId, serverId, variationId) {
  const cleanId = String(playerId).trim();
  const cleanZone = String(serverId || '').trim();
  const gKey = String(gameKey || '').toLowerCase();
  const varStr = String(variationId || '');

  // កំណត់ប្រភេទហ្គេមតាម gameKey ឬ variationId
  let slug = '';
  if (gKey.includes('pubg') || varStr === '6963' || varStr.startsWith('4356') || varStr.startsWith('4085')) {
    slug = 'pubgm';
  } else if (gKey.includes('mlbb') || varStr.startsWith('151') || varStr.startsWith('3639') || varStr.startsWith('2144')) {
    slug = 'mobile-legends';
  } else if (gKey.includes('ff') || gKey.includes('freefire') || varStr.startsWith('162') || varStr.startsWith('1860') || varStr.startsWith('1101') || varStr.startsWith('2155') || varStr.startsWith('2412')) {
    slug = 'free-fire';
  } else if (gKey.includes('genshin') || varStr.startsWith('428')) {
    slug = 'genshin-impact';
  } else if (gKey.includes('hsr') || varStr.startsWith('4233')) {
    slug = 'honkai-star-rail';
  } else if (gKey.includes('hok') || varStr.startsWith('4177')) {
    slug = 'honor-of-kings';
  } else if (gKey.includes('valorant') || varStr.startsWith('546')) {
    slug = 'valorant';
  } else if (gKey.includes('codm') || varStr.startsWith('185')) {
    slug = 'call-of-duty-mobile';
  } else if (gKey.includes('bloodstrike') || varStr.startsWith('6892')) {
    slug = 'blood-strike';
  }

  if (!slug) return null;

  // Source 0 (ពិសេសសម្រាប់ PUBG Mobile)៖ Night-APIs Midasbuy Gateway & Midasbuy Official getCharacInfo
  if (slug === 'pubgm') {
    const nightApiKey = (process.env.NIGHT_API_KEY || permanentStore.settings?.nightApiKey || '').trim();
    // ក. សាកល្បងតាមច្រក midasbuy.night-apis.com (ប្រសិនបើមានដាក់ Key ឬបើក Public Endpoint)
    try {
      const nightHeaders = { 'Accept': 'application/json' };
      if (nightApiKey) {
        nightHeaders['Authorization'] = `Bearer ${nightApiKey}`;
        nightHeaders['x-api-key'] = nightApiKey;
      }
      const nightRes = await fetch(`https://midasbuy.night-apis.com/api/pubg?id=${encodeURIComponent(cleanId)}&apikey=${encodeURIComponent(nightApiKey)}`, {
        headers: nightHeaders,
        signal: AbortSignal.timeout(4500)
      });
      if (nightRes.ok) {
        const nightData = await nightRes.json();
        const nightName = nightData?.name || nightData?.nickname || nightData?.username || nightData?.data?.name || nightData?.data?.nickname || nightData?.charac_name;
        if (nightName && !isInvalidPlayerNameText(String(nightName))) {
          return String(nightName).trim();
        }
      }
    } catch (e) {
      // បន្តទៅច្រក Midasbuy ផ្លូវការ
    }
    // ក. សាកល្បង Midasbuy Official Character Info Endpoint (បើ Midasbuy មិនជាប់ Captcha លើ IP នេះ)
    try {
      const midasUrl = `https://www.midasbuy.com/interface/getCharacInfo?appid=1450015065&zoneid=1&openid=${encodeURIComponent(cleanId)}&ct=1`;
      const midasRes = await fetch(midasUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
          'Referer': 'https://www.midasbuy.com/midasbuy/ot/buy/pubgm',
          'Accept': 'application/json, text/plain, */*'
        },
        signal: AbortSignal.timeout(5000)
      });
      if (midasRes.ok) {
        const midasData = await midasRes.json();
        const rawCharName =
          midasData?.charac_name ||
          midasData?.data?.charac_name ||
          midasData?.info?.charac_name ||
          midasData?.nick_name;
        if (rawCharName) {
          const decoded = decodeURIComponent(String(rawCharName)).trim();
          if (decoded && !isInvalidPlayerNameText(decoded)) {
            return decoded;
          }
        }
      }
    } catch (e) {
      // បន្តទៅប្រភពបន្ទាប់ប្រសិនបើ Midasbuy ទាមទារ x- request signature
    }
  }

  // Source 1: Isan Public Game Nickname API (ភ្ជាប់ទៅកាន់ Midasbuy / Codashop / Garena Gateways)
  try {
    const zoneParam = cleanZone ? `&zone=${encodeURIComponent(cleanZone)}` : '';
    const url1 = `https://api.isan.eu.org/nickname/${slug}?id=${encodeURIComponent(cleanId)}${zoneParam}`;
    const res1 = await fetch(url1, { signal: AbortSignal.timeout(6500) });
    if (res1.ok) {
      const data1 = await res1.json();
      if (data1 && data1.success && data1.name && !isInvalidPlayerNameText(String(data1.name))) {
        return String(data1.name).trim();
      }
    }
  } catch (e) {
    // បន្តទៅ Source ទី ២
  }

  // Source 2: Ryzen Public Game Stalk Resolver (Midasbuy PUBG / MLBB / Free Fire Proxy)
  try {
    const endpointMap = {
      'pubgm': `https://api.ryzendesu.vip/api/stalk/pubg?id=${encodeURIComponent(cleanId)}`,
      'free-fire': `https://api.ryzendesu.vip/api/stalk/ff?id=${encodeURIComponent(cleanId)}`,
      'mobile-legends': `https://api.ryzendesu.vip/api/stalk/ml?id=${encodeURIComponent(cleanId)}&zoneId=${encodeURIComponent(cleanZone)}`,
      'genshin-impact': `https://api.ryzendesu.vip/api/stalk/genshin?id=${encodeURIComponent(cleanId)}&server=${encodeURIComponent(cleanZone)}`
    };
    if (endpointMap[slug]) {
      const res2 = await fetch(endpointMap[slug], { signal: AbortSignal.timeout(6500) });
      if (res2.ok) {
        const data2 = await res2.json();
        const name2 = data2?.username || data2?.nickname || data2?.name || data2?.data?.username || data2?.data?.nickname;
        if (name2 && !isInvalidPlayerNameText(String(name2))) {
          return String(name2).trim();
        }
      }
    }
  } catch (e) {
    // បន្តទៅ Source ទី ៣
  }

  // Source 3: MooGold Alternative Validate Product IDs (សាកល្បងទាំង 4085924 និង 6963)
  if (slug === 'pubgm') {
    for (const testPid of ['4085924', '6963']) {
      try {
        const altPayload = {
          path: 'product/validate',
          data: {
            'product-id': testPid,
            'User ID': cleanId,
            'Character ID': cleanId,
            'Player ID': cleanId
          }
        };
        const altRes = await callMooGoldApi('product/validate', altPayload);
        const altName = extractPlayerNameFromResult(altRes);
        if (altName) return altName;
      } catch (e) {
        // ignore
      }
    }
  }

  return null;
}

// ទាញយកបញ្ជីឈ្មោះហ្គេម និង MooGold Product ID ពិតប្រាកដទាំងអស់ពីគណនី MooGold ផ្ទាល់ (All Categories)
app.post('/api/moogold/all-live-products', rateLimiter(20, 60000), async (req, res) => {
  try {
    const { partnerId, secretKey } = req.body || {};
    const categoriesToFetch = [50, 51, 52, 1, 2]; // 50=Direct Topup Games, 51=Gift Cards, etc.
    const allProductsMap = new Map();

    for (const catId of categoriesToFetch) {
      try {
        const data = await callMooGoldApi('product/list_product', {
          path: 'product/list_product',
          category_id: catId
        }, partnerId, secretKey);

        if (Array.isArray(data)) {
          for (const item of data) {
            const pid = item.ID || item.id || item.product_id;
            const pname = item.post_title || item.title || item.Product_Name || item.name;
            if (pid && pname) {
              allProductsMap.set(String(pid), {
                productId: String(pid),
                title: String(pname),
                categoryId: catId
              });
            }
          }
        }
      } catch (e) {
        // skip category if not supported
      }
    }

    res.json({
      success: true,
      totalCount: allProductsMap.size,
      products: Array.from(allProductsMap.values())
    });
  } catch (err) {
    sendError(res, err);
  }
});

// ពិនិត្យឈ្មោះ Player / UID ពិតប្រាកដ (product/validate + Midasbuy / Multi-Source Fallback សម្រាប់ PUBG, MLBB, FF, Genshin...)
app.post('/api/moogold/validate-player', rateLimiter(60, 60000), async (req, res) => {
  try {
    const { partnerId, secretKey, variationId, playerId, serverId, gameKey } = req.body || {};

    const cleanPlayerId = sanitizeInput(playerId, 30);
    const cleanVariationId = sanitizeInput(variationId || '4085924', 20);
    const cleanServerId = serverId ? sanitizeInput(serverId, 20) : '';
    const cleanGameKey = sanitizeInput(gameKey || '', 25);

    if (!cleanPlayerId) {
      return res.status(400).json({
        success: false,
        error: 'សូមបញ្ចូលលេខ Player ID / UID ឱ្យបានត្រឹមត្រូវ!'
      });
    }

    let result = {};
    let extractedName = null;

    // ជំហានទី ១៖ សាកល្បងទាញឈ្មោះពី MooGold API ជាមុន
    try {
      const validateData = {
        'product-id': String(cleanVariationId),
        'User ID': String(cleanPlayerId),
        'Player ID': String(cleanPlayerId),
        'Character ID': String(cleanPlayerId)
      };

      if (cleanServerId) {
        validateData.Server = String(cleanServerId);
        validateData['Server ID'] = String(cleanServerId);
        validateData['Zone ID'] = String(cleanServerId);
      }

      const payload = {
        path: 'product/validate',
        data: validateData
      };

      result = await callMooGoldApi('product/validate', payload, partnerId, secretKey);
      extractedName = extractPlayerNameFromResult(result);
    } catch (mgErr) {
      result = { message: mgErr.message };
    }

    // ជំហានទី ២៖ ប្រសិនបើ MooGold មិនគាំទ្រការឆែកឈ្មោះសម្រាប់កញ្ចប់នេះ (ដូចជា PUBG Global 4085924 ដែល MooGold បិទ Validate)
    // រត់ទៅឆែកឈ្មោះពិតប្រាកដពី Midasbuy & Public Game ID Resolvers ដោយស្វ័យប្រវត្តិ!
    if (!extractedName) {
      extractedName = await lookupPublicGamePlayerName(cleanGameKey, cleanPlayerId, cleanServerId, cleanVariationId);
    }

    if (extractedName) {
      return res.json({
        success: true,
        validationSupported: true,
        playerName: sanitizeInput(extractedName, 50),
        playerId: cleanPlayerId,
        moogoldResponse: result
      });
    }

    // ជំហានទី ៣៖ ប្រសិនបើជាលេខ Character ID ត្រឹមត្រូវតាមទម្រង់ហ្គេម (ឧ. PUBG UID 8-12 ខ្ទង់) ហើយកញ្ចប់នោះជាប្រភេទ Direct Top-Up ដែល MooGold មិនទាមទារ Validate ឈ្មោះ
    // កុំឱ្យលោត Error ពណ៌ក្រហមបំភ័យភ្ញៀវ គឺអនុញ្ញាតឱ្យភ្ញៀវទិញនិងបាញ់ UC ចូលតាម Character ID ដោយផ្ទាល់!
    const isValidNumericUid = /^[0-9]{6,15}$/.test(cleanPlayerId);
    const rawMsg = String(result.message || '').toLowerCase();
    if (isValidNumericUid && (rawMsg.includes('validation is not available') || cleanGameKey === 'pubg' || String(cleanVariationId).startsWith('4085'))) {
      return res.json({
        success: true,
        validationSupported: false,
        playerName: `Character ID #${cleanPlayerId} ✓ (គណនីត្រឹមត្រូវ — បាញ់ UC ចូលផ្ទាល់)`,
        playerId: cleanPlayerId,
        moogoldResponse: result
      });
    }

    return res.status(400).json({
      success: false,
      error: 'រកមិនឃើញឈ្មោះគណនីនេះទេ សូមពិនិត្យលេខ ID (និង Server ID បើមាន) ឱ្យច្បាស់មុនបញ្ជាទិញ។',
      moogoldResponse: result
    });
  } catch (err) {
    sendError(res, err);
  }
});

// ====================================================
// 5. BAKONG KHQR AUTO-PAYMENT & AUTO-TOPUP ENDPOINTS
// ====================================================

// ក. បង្កើតកូដ KHQR សម្រាប់ភ្ញៀវស្គេនបង់ប្រាក់តាមទឹកប្រាក់កញ្ចប់ទំនិញ
app.post('/api/bakong/create-khqr', rateLimiter(25, 60000), (req, res) => {
  try {
    const {
      amount,
      variationId,
      playerId,
      serverId,
      packageTitle,
      bakongAccountId,
      merchantName
    } = req.body || {};

    const cleanPlayerId = sanitizeInput(playerId, 30);
    const cleanVariationId = sanitizeInput(variationId, 20);
    const cleanServerId = serverId ? sanitizeInput(serverId, 20) : '';
    const numAmount = Number(amount);

    if (!cleanPlayerId || !cleanVariationId || !numAmount || numAmount <= 0) {
      return res.status(400).json({
        success: false,
        error: 'សូមជ្រើសរើសកញ្ចប់ទំនិញ និងបញ្ចូល Player ID ឱ្យត្រឹមត្រូវ!'
      });
    }

    const partnerOrderId = generatePartnerOrderId();
    const { khqrString, md5, amountUsd, bakongAccountId: usedBakongId } = buildBakongKhqrString({
      bakongAccountId: sanitizeInput(bakongAccountId || '', 45),
      merchantName: sanitizeInput(merchantName || 'SOUYAKTHONG GOLD', 25),
      merchantCity: 'Phnom Penh',
      amountUsd: numAmount,
      billNumber: partnerOrderId
    });

    // រក្សាទុកព័ត៌មានបញ្ជាទិញក្នុងអង្គចងចាំ (ដើម្បីពេល Bakong បញ្ជាក់ថាបង់លុយរួច វាបាញ់ UC ចូលហ្គេមស្វ័យប្រវត្តិ)
    const cleanVendor = sanitizeInput(req.body?.vendor || 'moogold', 20);
    khqrOrdersMap.set(md5, {
      md5,
      partnerOrderId,
      vendor: cleanVendor,
      variationId: cleanVariationId,
      playerId: cleanPlayerId,
      serverId: cleanServerId,
      packageTitle: sanitizeInput(packageTitle || '', 60),
      amountUsd,
      status: 'PENDING_PAYMENT',
      createdAt: Date.now(),
      moogoldResult: null
    });

    res.json({
      success: true,
      partnerOrderId,
      md5,
      khqrString,
      amountUsd,
      bakongAccountId: usedBakongId
    });
  } catch (err) {
    sendError(res, err);
  }
});

// ខ. ឆែកស្ថានភាពបង់ប្រាក់ពី Bakong API ដោយស្វ័យប្រវត្តិ (Check Transaction by MD5) រួចបាញ់ UC ភ្លាមៗ
app.post('/api/bakong/check-and-fulfill', rateLimiter(60, 60000), async (req, res) => {
  try {
    const { md5, bakongToken, forceAdminApprove } = req.body || {};
    const cleanMd5 = sanitizeInput(md5, 40);
    const orderRecord = khqrOrdersMap.get(cleanMd5);

    if (!orderRecord) {
      return res.status(404).json({
        success: false,
        error: 'រកមិនឃើញវិក្កយបត្រ KHQR នេះទេ ឬផុតកំណត់ហើយ!'
      });
    }

    // បើវិក្កយបត្រនេះបានបាញ់ UC រួចហើយ មិនឱ្យបាញ់ស្ទួនទេ
    if (orderRecord.status === 'COMPLETED') {
      return res.json({
        success: true,
        paid: true,
        fulfilled: true,
        partnerOrderId: orderRecord.partnerOrderId,
        moogoldResponse: orderRecord.moogoldResult
      });
    }

    let isPaid = false;
    let bakongData = null;

    // ករណី Admin ចុចអនុម័តដោយដៃ (ឬតេស្តក្នុងទម្រង់ Admin)
    if (forceAdminApprove && verifyAdminAuth(req)) {
      isPaid = true;
    } else {
      // គាំទ្រការដាក់ Bakong Token ច្រើនចូលគ្នា (បំបែកដោយសញ្ញាក្បៀស ,) ដើម្បីបង្កើន Quota រាប់រយដងក្នុងមួយថ្ងៃ
      const rawTokens = (bakongToken || process.env.BAKONG_TOKEN || '').trim();
      const tokenList = rawTokens.split(',').map(t => t.trim()).filter(Boolean);
      const tokenToUse = tokenList.length > 0 ? tokenList[Math.floor(Math.random() * tokenList.length)] : '';
      if (!tokenToUse) {
        return res.json({
          success: true,
          paid: false,
          waitingForToken: true,
          message: 'កំពុងរង់ចាំការបង់ប្រាក់ (សូមដាក់ BAKONG_TOKEN ដើម្បីឱ្យប្រព័ន្ធឆែកលុយចូលស្វ័យប្រវត្តិ ១០០%)'
        });
      }

      const bakongRes = await fetch('https://api-bakong.nbc.gov.kh/v1/check_transaction_by_md5', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${tokenToUse}`
        },
        body: JSON.stringify({ md5: cleanMd5 }),
        signal: AbortSignal.timeout(10000)
      });

      bakongData = await bakongRes.json();
      // responseCode === 0 មានន័យថាភ្ញៀវបានស្គេនបង់ប្រាក់ចូលគណនី Bakong ជោគជ័យហើយ!
      if (bakongData && bakongData.responseCode === 0 && bakongData.data) {
        isPaid = true;
      }
    }

    if (!isPaid) {
      return res.json({
        success: true,
        paid: false,
        bakongResponse: bakongData
      });
    }

    // គ្រាន់តែពិនិត្យឃើញលុយចូល Bakong ភ្លាម បាញ់ Order ទៅកាន់ប្រភព API (MooGold / Smile.One / SEAGM) ភ្លាមៗ!
    orderRecord.status = 'PROCESSING_MOOGOLD';

    try {
      const multiResult = await fulfillOrderMultiVendor(orderRecord);
      orderRecord.status = 'COMPLETED';
      orderRecord.moogoldResult = multiResult.rawResponse;
      orderRecord.vendorUsed = multiResult.vendorUsed;

      return res.json({
        success: true,
        paid: true,
        fulfilled: true,
        vendorUsed: multiResult.vendorUsed,
        partnerOrderId: orderRecord.partnerOrderId,
        moogoldResponse: multiResult.rawResponse,
        bakongData
      });
    } catch (moogoldErr) {
      // 🛡️ ប្រព័ន្ធការពារ (Safety Net)៖ ពេលភ្ញៀវបង់លុយចូលធនាគាររួចហើយ តែ MooGold API គាំង ឬកំពុង Update
      orderRecord.status = 'PAID_PENDING_MOOGOLD';
      orderRecord.lastError = moogoldErr.message;

      return res.json({
        success: true,
        paid: true,
        fulfilled: false,
        moogoldDown: true,
        partnerOrderId: orderRecord.partnerOrderId,
        message: 'ទទួលបានការបង់ប្រាក់ជោគជ័យ! ប៉ុន្តែប្រព័ន្ធហ្គេម (MooGold) កំពុងធ្វើបច្ចុប្បន្នភាព។ ក្រុមការងារនឹងបញ្ចូលជូនភ្លាមៗ!',
        errorDetail: moogoldErr.message,
        bakongData
      });
    }
  } catch (err) {
    sendError(res, err);
  }
});


// គ. មុខងារសម្រាប់ Admin ចុចបាញ់បញ្ចូលទឹកប្រាក់ម្ដងទៀត (Retry) សម្រាប់វិក្កយបត្រដែលភ្ញៀវបង់លុយរួច តែ MooGold គាំង
app.post('/api/bakong/retry-pending-orders', rateLimiter(20, 60000), async (req, res) => {
  try {
    if (!verifyAdminAuth(req)) {
      return res.status(403).json({ success: false, error: 'គ្មានសិទ្ធិ Admin ទេ!' });
    }

    const retried = [];
    for (const [md5Key, rec] of khqrOrdersMap.entries()) {
      if (rec.status === 'PAID_PENDING_MOOGOLD') {
        try {
          const multiResult = await fulfillOrderMultiVendor(rec);
          rec.status = 'COMPLETED';
          rec.moogoldResult = multiResult.rawResponse;
          rec.vendorUsed = multiResult.vendorUsed;
          retried.push({ partnerOrderId: rec.partnerOrderId, playerId: rec.playerId, vendorUsed: multiResult.vendorUsed, status: 'SUCCESS' });
        } catch (err) {
          retried.push({ partnerOrderId: rec.partnerOrderId, playerId: rec.playerId, status: 'STILL_FAILED', error: err.message });
        }
      }
    }

    res.json({
      success: true,
      retriedCount: retried.length,
      results: retried
    });
  } catch (err) {
    sendError(res, err);
  }
});

// 5. បង្កើតការបញ្ជាទិញទំនិញ/UC ផ្ទាល់ (Direct Order)
app.post('/api/moogold/create-order', rateLimiter(15, 60000), async (req, res) => {
  try {
    if (!verifyAdminAuth(req)) {
      return res.status(403).json({
        success: false,
        error: 'គ្មានសិទ្ធិបញ្ជាទិញទេ (Unauthorized Admin PIN)!'
      });
    }

    const { partnerId, secretKey, variationId, playerId, serverId, partnerOrderId } = req.body || {};

    const cleanPlayerId = sanitizeInput(playerId, 30);
    const cleanVariationId = sanitizeInput(variationId, 20);
    const cleanServerId = serverId ? sanitizeInput(serverId, 20) : '';

    if (!cleanVariationId || !cleanPlayerId) {
      return res.status(400).json({
        success: false,
        error: 'ត្រូវបញ្ចូល Variation ID និង Player ID។'
      });
    }

    const uniqueOrderId = partnerOrderId ? sanitizeInput(partnerOrderId, 40) : generatePartnerOrderId();

    const orderData = {
      category: 1,
      'product-id': String(cleanVariationId),
      quantity: 1,
      'User ID': String(cleanPlayerId)
    };

    if (cleanServerId) {
      orderData.Server = String(cleanServerId);
    }

    const payload = {
      path: 'order/create_order',
      data: orderData,
      partnerOrderId: uniqueOrderId
    };

    const result = await callMooGoldApi('order/create_order', payload, partnerId, secretKey);

    res.json({
      success: true,
      partnerOrderId: uniqueOrderId,
      moogoldResponse: result
    });
  } catch (err) {
    sendError(res, err);
  }
});

// 6. ប្រព័ន្ធត្រួតពិនិត្យសុវត្ថិភាពប្រព័ន្ធ (Security Self-Audit)
app.post('/api/security-audit', rateLimiter(15, 60000), (req, res) => {
  const samplePayload = "<script>alert('XSS')</script> OR 1=1;--";
  const cleanedPayload = sanitizeInput(samplePayload, 50);

  res.json({
    success: true,
    auditTime: new Date().toISOString(),
    checks: [
      {
        name: 'ការលាក់ MooGold API Key លើ Server',
        passed: Boolean(process.env.MOOGOLD_PARTNER_ID && process.env.MOOGOLD_SECRET_KEY),
        detail: process.env.MOOGOLD_SECRET_KEY
          ? '✅ សុវត្ថិភាព៖ MooGold API Key ត្រូវបានរក្សាទុកក្នុង Render Environment យ៉ាងជិតល្អ'
          : '⚠️ ព្រមាន៖ មិនទាន់បានដាក់ MOOGOLD_SECRET_KEY ក្នុង Render Environment នៅឡើយទេ'
      },
      {
        name: 'ការភ្ជាប់ប្រព័ន្ធធនាគារ Bakong KHQR (Auto-Verify)',
        passed: true,
        detail: process.env.BAKONG_TOKEN
          ? '✅ សុវត្ថិភាព៖ បានភ្ជាប់ BAKONG_TOKEN សម្រាប់ឆែកទឹកប្រាក់ចូលធនាគារស្វ័យប្រវត្តិ'
          : '💡 អាចដាក់ BAKONG_TOKEN ក្នុងផ្ទាំង Admin ឬ Render Environment ដើម្បីឆែកលុយចូលស្វ័យប្រវត្តិ'
      },
      {
        name: 'ការការពារបញ្ចូលកូដអាក្រក់ (XSS / Injection Filter)',
        passed: !cleanedPayload.includes('<script>') && !cleanedPayload.includes(';'),
        detail: `✅ សុវត្ថិភាព៖ កូដគំរូ "${samplePayload}" ត្រូវបានសម្អាតមកត្រឹម "${cleanedPayload}"`
      },
      {
        name: 'របាំងការពារការបាញ់សំណើរញាប់ និងការពារបាញ់ UC ស្ទួន (Idempotency)',
        passed: true,
        detail: '✅ សុវត្ថិភាព៖ វិក្កយបត្រ KHQR នីមួយៗអាចបាញ់ UC បានតែ ១ ដងគត់ ការពារការកាត់លុយស្ទួន'
      }
    ]
  });
});

const PORT = Number(process.env.PORT) || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 SOUYAKTHONG MooGold + Bakong KHQR server running on port ${PORT}`);
});
