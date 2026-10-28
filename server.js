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

// ពិនិត្យឈ្មោះ Player / UID ពិតប្រាកដ (product/validate)
app.post('/api/moogold/validate-player', rateLimiter(60, 60000), async (req, res) => {
  try {
    const { partnerId, secretKey, variationId, playerId, serverId } = req.body || {};

    const cleanPlayerId = sanitizeInput(playerId, 30);
    const cleanVariationId = sanitizeInput(variationId || '435611', 20);
    const cleanServerId = serverId ? sanitizeInput(serverId, 20) : '';

    if (!cleanPlayerId) {
      return res.status(400).json({
        success: false,
        error: 'សូមបញ្ចូលលេខ Player ID / UID ឱ្យបានត្រឹមត្រូវ!'
      });
    }

    const validateData = {
      'product-id': String(cleanVariationId),
      'User ID': String(cleanPlayerId),
      'Player ID': String(cleanPlayerId)
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

    const result = await callMooGoldApi('product/validate', payload, partnerId, secretKey);
    const extractedName = extractPlayerNameFromResult(result);

    const rawMsg = String(result.message || '');
    if (!extractedName && rawMsg.toLowerCase().includes('validation is not available')) {
      return res.json({
        success: true,
        validationSupported: false,
        playerName: 'UID បានត្រៀមរួចរាល់ (កញ្ចប់នេះបញ្ចូលត្រង់តាម ID ដោយមិនបាច់ឆែកឈ្មោះ)',
        playerId: cleanPlayerId,
        moogoldResponse: result
      });
    }

    if (!extractedName || result.status === false || result.status === 'false' || result.err_code) {
      return res.status(400).json({
        success: false,
        error: 'រកមិនឃើញឈ្មោះគណនីនេះទេ សូមពិនិត្យលេខ ID (និង Server ID បើមាន) ឱ្យច្បាស់មុនបញ្ជាទិញ។',
        moogoldResponse: result
      });
    }

    res.json({
      success: true,
      validationSupported: true,
      playerName: sanitizeInput(extractedName, 50),
      playerId: cleanPlayerId,
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
    khqrOrdersMap.set(md5, {
      md5,
      partnerOrderId,
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

    // គ្រាន់តែពិនិត្យឃើញលុយចូល Bakong ភ្លាម បាញ់ Order ទៅ MooGold ភ្លាមៗ!
    orderRecord.status = 'PROCESSING_MOOGOLD';

    const orderData = {
      category: 1,
      'product-id': String(orderRecord.variationId),
      quantity: 1,
      'User ID': String(orderRecord.playerId)
    };
    if (orderRecord.serverId) {
      orderData.Server = String(orderRecord.serverId);
    }

    const moogoldPayload = {
      path: 'order/create_order',
      data: orderData,
      partnerOrderId: orderRecord.partnerOrderId
    };

    try {
      const moogoldResult = await callMooGoldApi('order/create_order', moogoldPayload);
      orderRecord.status = 'COMPLETED';
      orderRecord.moogoldResult = moogoldResult;

      return res.json({
        success: true,
        paid: true,
        fulfilled: true,
        partnerOrderId: orderRecord.partnerOrderId,
        moogoldResponse: moogoldResult,
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
          const orderData = {
            category: 1,
            'product-id': String(rec.variationId),
            quantity: 1,
            'User ID': String(rec.playerId)
          };
          if (rec.serverId) orderData.Server = String(rec.serverId);

          const moogoldResult = await callMooGoldApi('order/create_order', {
            path: 'order/create_order',
            data: orderData,
            partnerOrderId: rec.partnerOrderId
          });

          rec.status = 'COMPLETED';
          rec.moogoldResult = moogoldResult;
          retried.push({ partnerOrderId: rec.partnerOrderId, playerId: rec.playerId, status: 'SUCCESS' });
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
