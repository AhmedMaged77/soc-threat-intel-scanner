// index.js
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const { vtLookup } = require('./services/vt');
const { urlscanScan } = require('./services/urlscan');
const { abuseLookup } = require('./services/abuseipdb');
const { whoisLookup } = require('./services/whois');
const { geminiSummarize } = require('./services/gemini');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Enable CORS for Angular dev server & allow other clients if needed
app.use(cors({
  origin: [
    'http://localhost:4200', 
    'http://127.0.0.1:4200'
  ],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));


app.post('/scan', async (req, res) => {
  const { target } = req.body;
  if (!target) {
    return res.status(400).json({ error: 'target is required in body' });
  }

  let type = null;
  if (/^https?:\/\//i.test(target)) type = 'url';
  else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(target)) type = 'ip';
  else if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{64}$/.test(target)) type = 'hash';
  else if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(target)) type = 'domain';
  else return res.status(400).json({ error: 'Invalid target format' });

  const analysis = {};

  try {
    if (type === 'url') {
      const vtPromise = vtLookup('url', target).catch(e => ({ error: e.message }));
      const urlscanPromise = urlscanScan(target).catch(e => ({ error: e.message }));
      const [vtRes, urlscanRes] = await Promise.all([vtPromise, urlscanPromise]);
      analysis.virustotal = vtRes;
      analysis.urlscan = urlscanRes;
    } else if (type === 'ip') {
      const vtPromise = vtLookup('ip', target).catch(e => ({ error: e.message }));
      const abusePromise = abuseLookup(target).catch(e => ({ error: e.message }));
      const [vtRes, abuseRes] = await Promise.all([vtPromise, abusePromise]);
      analysis.virustotal = vtRes;
      analysis.abuseipdb = abuseRes;
    } else if (type === 'hash') {
      analysis.virustotal = await vtLookup('file', target).catch(e => ({ error: e.message }));
    } else if (type === 'domain') {
      const vtPromise = vtLookup('domain', target).catch(e => ({ error: e.message }));
      const whoisPromise = whoisLookup(target).catch(e => ({ error: e.message }));
      const [vtRes, whoisRes] = await Promise.all([vtPromise, whoisPromise]);
      analysis.virustotal = vtRes;
      analysis.whois = whoisRes;
    }

    try {
      const geminiRes = await geminiSummarize(type, target, analysis).catch(e => ({ error: e.message }));
      analysis.gemini = geminiRes;
    } catch (gErr) {
      analysis.gemini = { error: gErr.message };
    }

    return res.json({ type, target, analysis });
  } catch (err) {
    console.error('Unified scan error:', err);
    return res.status(500).json({ error: 'Internal error during scanning', details: err.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Scanner running on http://localhost:${PORT}`);
});
