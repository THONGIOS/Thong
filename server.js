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
