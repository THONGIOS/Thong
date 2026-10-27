require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();

app.use(helmet());
// អនុញ្ញាតឱ្យ Frontend (Netlify) ហៅចូលបានដោយមិនជាប់បម្រាម CORS
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

// អនុគមន៍បង្កើតលេខកូដបញ្ជាទិញថ្មីរហូត មិនឱ្យជាន់គ្នា (Unique Partner Order ID)
function generatePartnerOrderId() {
  const timestamp = Date.now();
  const randomStr = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `THONG-${timestamp}-${randomStr}`;
}

async function callMooGoldApi(endpointPath, payloadObj, customPartnerId, customSecretKey) {
  const partnerId = customPartnerId || process.env.MOOGOLD_PARTNER_ID;
  const secretKey = customSecretKey || process.env.MOOGOLD_SECRET_KEY;

  if (!partnerId || !secretKey) {
    throw new Error('សូមដាក់ MOOGOLD_PARTNER_ID និង MOOGOLD_SECRET_KEY នៅក្នុង Environment របស់ Render!');
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

// 2. បង្កើតការបញ្ជាទិញ (order/create_order) + Generate Partner Order ID ថ្មីរហូត
app.post('/api/moogold/create-order', async (req, res) => {
  try {
    const { partnerId, secretKey, variationId, playerId, serverId, partnerOrderId } = req.body || {};

    if (!variationId || !playerId) {
      return res.status(400).json({
        error: 'ត្រូវបញ្ចូល Variation ID និង Player ID។'
      });
    }

    // បើមិនមានផ្ញើ partnerOrderId មកទេ វានឹងបង្កើតលេខកូដថ្មីដោយស្វ័យប្រវត្តិគ្រប់ពេល Top-up
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

const PORT = Number(process.env.PORT) || 3000;

app.listen(PORT, () => {
  console.log(`🚀 MooGold API server running on port ${PORT}`);
});
