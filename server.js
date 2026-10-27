require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || '*'
}));
app.use(express.json({ limit: '5mb' }));

app.get('/', (req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'SOUYAKTHONG MooGold API Server Running 24/7'
  });
});

// ចូលទៅកាន់ https://thong-1.onrender.com/my-ip ដើម្បីមើលលេខ IP ពិតប្រាកដរបស់ Server យកទៅដាក់ក្នុង MooGold Whitelist
app.get('/my-ip', async (req, res) => {
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

function generatePartnerOrderId() {
  const timestamp = Date.now();
  const randomStr = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `THONG-${timestamp}-${randomStr}`;
}

async function callMooGoldApi(endpointPath, payloadObj, customPartnerId, customSecretKey) {
  const partnerId = customPartnerId || process.env.MOOGOLD_PARTNER_ID;
  const secretKey = customSecretKey || process.env.MOOGOLD_SECRET_KEY;

  if (!partnerId || !secretKey) {
    throw new Error('សូមដាក់ MOOGOLD_PARTNER_ID និង MOOGOLD_SECRET_KEY ឱ្យបានត្រឹមត្រូវ!');
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
    error: err.message || 'Server error.',
    details: err.details || null
  });
}

// 1. ឆែកសមតុល្យទឹកប្រាក់ (user/balance)
app.post('/api/moogold/balance', async (req, res) => {
  try {
    const { partnerId, secretKey } = req.body || {};
    const payload = { path: 'user/balance' };
    const data = await callMooGoldApi('user/balance', payload, partnerId, secretKey);
    res.json(data);
  } catch (err) {
    sendError(res, err);
  }
});

// 2. បង្កើតការបញ្ជាទិញ (order/create_order)
app.post('/api/moogold/create-order', async (req, res) => {
  try {
    const { partnerId, secretKey, variationId, playerId, serverId, partnerOrderId } = req.body || {};

    if (!variationId || !playerId) {
      return res.status(400).json({
        error: 'ត្រូវបញ្ចូល Variation ID និង Player ID។'
      });
    }

    const uniqueOrderId = partnerOrderId || generatePartnerOrderId();

    const orderData = {
      category: 1,
      'product-id': String(variationId),
      quantity: 1,
      'User ID': String(playerId)
    };

    if (serverId) {
      orderData.Server = String(serverId);
    }

    const payload = {
      path: 'order/create_order',
      data: orderData,
      partnerOrderId: uniqueOrderId
    };

    const result = await callMooGoldApi(
      'order/create_order',
      payload,
      partnerId,
      secretKey
    );

    res.json({
      success: true,
      partnerOrderId: uniqueOrderId,
      moogoldResponse: result
    });
  } catch (err) {
    sendError(res, err);
  }
});
// 3. ពិនិត្យឈ្មោះ Player / Validate Player ID (តាមស្ដង់ដារ product/validate របស់ MooGold)
app.post('/api/moogold/validate-player', async (req, res) => {
  try {
    const { partnerId, secretKey, variationId, playerId, serverId } = req.body || {};

    if (!variationId || !playerId) {
      return res.status(400).json({
        error: 'ត្រូវបញ្ចូល Variation ID និង Player ID។'
      });
    }

    const validateData = {
      'product-id': String(variationId),
      'User ID': String(playerId)
    };

    if (serverId) {
      validateData.Server = String(serverId);
    }

    const payload = {
      path: 'product/validate',
      data: validateData
    };

    const result = await callMooGoldApi(
      'product/validate',
      payload,
      partnerId,
      secretKey
    );

    res.json({
      success: true,
      moogoldResponse: result
    });
  } catch (err) {
    sendError(res, err);
  }
});
const PORT = Number(process.env.PORT) || 3000;

app.listen(PORT, () => {
  console.log(`🚀 MooGold API server running on port ${PORT}`);
});
