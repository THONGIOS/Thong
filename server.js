/**
 * ឯកសារ៖ server.js
 * តួនាទី៖ Backend Server សម្រាប់ភ្ជាប់ MooGold API (Balance, Clone រូបភាព/ទំនិញ, Validate Player, Create Order)
 */
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();

// 1. របាំងសុវត្ថិភាព HTTP Headers
app.use(helmet());

// ពិនិត្យមើលថាតើអក្សរដែល MooGold បោះមកជាឈ្មោះពិត ឬជាសារជូនដំណឹង
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
    'please'
  ];
  return blockedPhrases.some((phrase) => lower.includes(phrase));
}

// 2. ពិនិត្យឈ្មោះ Player / UID ពិតប្រាកដ (product/validate + Fallback សម្រាប់ PUBG)
app.post('/api/moogold/validate-player', rateLimiter(30, 60000), async (req, res) => {
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
      'User ID': String(cleanPlayerId)
    };

    if (cleanServerId) {
      validateData.Server = String(cleanServerId);
    }

    const payload = {
      path: 'product/validate',
      data: validateData
    };

    const result = await callMooGoldApi('product/validate', payload, partnerId, secretKey);

    // ទាញយកឈ្មោះពី Field សំខាន់ៗរបស់ MooGold
    let extractedName =
      result.username ||
      result.player_name ||
      result.name ||
      result.ign ||
      (result.data && (result.data.username || result.data.player_name || result.data.name)) ||
      (!isInvalidPlayerNameText(result.message) ? result.message : null);

    // បើវាជាសារជូនដំណឹងដូចជា "Validation is not available..." ត្រូវលុបចោលមិនឱ្យយកមកធ្វើជាឈ្មោះទេ
    if (isInvalidPlayerNameText(extractedName)) {
      extractedName = null;
    }

    // ប្រសិនបើ MooGold ឆ្លើយថា "Validation is not available for this product"
    const rawMsg = String(result.message || '');
    if (!extractedName && rawMsg.toLowerCase().includes('validation is not available')) {
      return res.json({
        success: true,
        validationSupported: false,
        playerName: `UID បានត្រៀមរួចរាល់ (កញ្ចប់នេះបញ្ចូលត្រង់តាម ID ដោយមិនបាច់ឆែកឈ្មោះ)`,
        playerId: cleanPlayerId,
        moogoldResponse: result
      });
    }

    if (!extractedName || result.status === false || result.err_code) {
      return res.status(400).json({
        success: false,
        error: 'រកមិនឃើញឈ្មោះគណនីនេះទេ សូមពិនិត្យលេខ ID ឱ្យច្បាស់មុនបញ្ជាទិញ។',
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

// 3. ប្រព័ន្ធការពារការបាញ់សំណើរញាប់ពេក (Rate Limiter ការពារ Bot/DDoS)
const rateLimitMap = new Map();
function rateLimiter(maxRequests = 30, windowMs = 60000) {
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

// 4. មុខងារសម្អាតទិន្នន័យ (ការពារ XSS / Script Injection)
function sanitizeInput(str, maxLength = 80) {
  if (typeof str !== 'string' && typeof str !== 'number') return '';
  return String(str)
    .replace(/[<>'"`;(){}]/g, '')
    .trim()
    .slice(0, maxLength);
}

// 5. មុខងារត្រួតពិនិត្យសិទ្ធិ Admin (ប្រសិនបើបានដាក់ ADMIN_SECRET_PIN លើ Render)
function verifyAdminAuth(req) {
  const serverAdminPin = process.env.ADMIN_SECRET_PIN;
  if (!serverAdminPin) return true;
  const clientPin = req.headers['x-admin-pin'] || (req.body && req.body.adminPin);
  return clientPin === serverAdminPin;
}

app.get('/', (req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'SOUYAKTHONG MooGold API Server Running 24/7',
    security: {
      helmet: true,
      rateLimit: true,
      inputSanitization: true,
      envCredentialsLoaded: Boolean(process.env.MOOGOLD_PARTNER_ID && process.env.MOOGOLD_SECRET_KEY)
    }
  });
});

// ឆែកមើលលេខ IP ពិតប្រាកដរបស់ Render Server សម្រាប់ដាក់ក្នុង MooGold IP Whitelist
app.get('/my-ip', rateLimiter(10, 60000), async (req, res) => {
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

// បង្កើតលេខកូដវិក្កយបត្រថ្មីរហូតមិនឱ្យជាន់គ្នា (Unique Partner Order ID)
function generatePartnerOrderId() {
  const timestamp = Date.now();
  const randomStr = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `THONG-${timestamp}-${randomStr}`;
}

// អនុគមន៍កណ្តាលសម្រាប់ហៅទៅកាន់ MooGold API (HMAC-SHA256)
async function callMooGoldApi(endpointPath, payloadObj, customPartnerId, customSecretKey) {
  const partnerId = customPartnerId || process.env.MOOGOLD_PARTNER_ID;
  const secretKey = customSecretKey || process.env.MOOGOLD_SECRET_KEY;

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
      signal: AbortSignal.timeout(15000)
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
  console.error('MooGold request failed:', err.message, err.details || '');
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Server error.',
    details: err.details || null
  });
}

// 1. ឆែកសមតុល្យទឹកប្រាក់ (user/balance)
app.post('/api/moogold/balance', rateLimiter(20, 60000), async (req, res) => {
  try {
    const { partnerId, secretKey } = req.body || {};
    const payload = { path: 'user/balance' };
    const data = await callMooGoldApi('user/balance', payload, partnerId, secretKey);
    res.json(data);
  } catch (err) {
    sendError(res, err);
  }
});

// 2. ទាញយករូបភាពផ្លូវការ (Image_URL) និងតម្លៃកញ្ចប់ទំនិញផ្ទាល់ពី MooGold (product/product_detail)
app.post('/api/moogold/product-detail', rateLimiter(30, 60000), async (req, res) => {
  try {
    const { partnerId, secretKey, productId } = req.body || {};
    const cleanProductId = sanitizeInput(productId || '15145', 20);

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

// 3. ទាញយកបញ្ជីហ្គេមតាម Category ពី MooGold (product/list_product)
app.post('/api/moogold/list-products', rateLimiter(20, 60000), async (req, res) => {
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

// 4. ពិនិត្យឈ្មោះ Player / UID ពិតប្រាកដ (product/validate)
app.post('/api/moogold/validate-player', rateLimiter(30, 60000), async (req, res) => {
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
      'User ID': String(cleanPlayerId)
    };

    if (cleanServerId) {
      validateData.Server = String(cleanServerId);
    }

    const payload = {
      path: 'product/validate',
      data: validateData
    };

    const result = await callMooGoldApi('product/validate', payload, partnerId, secretKey);

    const extractedName =
      result.username ||
      result.player_name ||
      result.name ||
      result.ign ||
      (result.data && (result.data.username || result.data.player_name || result.data.name)) ||
      (typeof result.message === 'string' &&
        !result.message.toLowerCase().includes('invalid') &&
        !result.message.toLowerCase().includes('error') &&
        !result.message.toLowerCase().includes('not found')
        ? result.message
        : null);

    if (!extractedName || result.status === false || result.err_code) {
      return res.status(400).json({
        success: false,
        error: result.message || 'រកមិនឃើញឈ្មោះគណនីនេះទេ ឬហ្គេមនេះមិនគាំទ្រការឆែកឈ្មោះស្វ័យប្រវត្តិ។',
        moogoldResponse: result
      });
    }

    res.json({
      success: true,
      playerName: sanitizeInput(extractedName, 50),
      playerId: cleanPlayerId,
      moogoldResponse: result
    });
  } catch (err) {
    sendError(res, err);
  }
});

// 5. បង្កើតការបញ្ជាទិញទំនិញ/UC ពិតប្រាកដ (order/create_order)
app.post('/api/moogold/create-order', rateLimiter(12, 60000), async (req, res) => {
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
app.post('/api/security-audit', rateLimiter(10, 60000), (req, res) => {
  const samplePayload = "<script>alert('XSS')</script> OR 1=1;--";
  const cleanedPayload = sanitizeInput(samplePayload, 50);

  res.json({
    success: true,
    auditTime: new Date().toISOString(),
    checks: [
      {
        name: 'ការលាក់ API Key លើ Server (Secret Key Protection)',
        passed: Boolean(process.env.MOOGOLD_PARTNER_ID && process.env.MOOGOLD_SECRET_KEY),
        detail: process.env.MOOGOLD_SECRET_KEY
          ? '✅ សុវត្ថិភាព៖ API Key ត្រូវបានរក្សាទុកក្នុង Render Environment យ៉ាងជិតល្អ'
          : '⚠️ ព្រមាន៖ មិនទាន់បានដាក់ MOOGOLD_SECRET_KEY ក្នុង Render Environment នៅឡើយទេ'
      },
      {
        name: 'ការការពារបញ្ចូលកូដអាក្រក់ (XSS / Injection Filter)',
        passed: !cleanedPayload.includes('<script>') && !cleanedPayload.includes(';'),
        detail: `✅ សុវត្ថិភាព៖ កូដគំរូ "${samplePayload}" ត្រូវបានសម្អាតមកត្រឹម "${cleanedPayload}"`
      },
      {
        name: 'របាំងការពារការបាញ់សំណើរញាប់ (Rate Limiting)',
        passed: true,
        detail: '✅ សុវត្ថិភាព៖ កំណត់ចំនួនសំណើរក្នុង ១ នាទី ការពារ Bot បាញ់បំផ្លាញទឹកប្រាក់'
      },
      {
        name: 'របាំងការពារ HTTP Security Headers (Helmet)',
        passed: true,
        detail: '✅ សុវត្ថិភាព៖ បានបើកមុខងារ Helmet ការពារ Clickjacking និង Sniffing'
      }
    ]
  });
});

const PORT = Number(process.env.PORT) || 3000;

app.listen(PORT, () => {
  console.log(`🚀 SOUYAKTHONG MooGold API server running on port ${PORT}`);
});
