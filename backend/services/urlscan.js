// services/urlscan.js
const axios = require('axios');
const delay = (ms) => new Promise(r => setTimeout(r, ms));

async function urlscanScan(target) {
  const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;
  if (!URLSCAN_API_KEY) throw new Error('URLSCAN_API_KEY not set');

  const submitResp = await axios.post(
    'https://urlscan.io/api/v1/scan/',
    { url: target },
    { headers: { 'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json' } }
  );

  const uuid = submitResp.data.uuid;
  const resultUrl = `https://urlscan.io/api/v1/result/${uuid}/`;
  const guiLink = `https://urlscan.io/result/${uuid}/`;

  let result = null;
  for (let i = 0; i < 12; i++) {
    try {
      const r = await axios.get(resultUrl);
      result = r.data;
      break;
    } catch (err) {
      if (err.response && err.response.status === 404) {
        await delay(5000);
      } else {
        throw err;
      }
    }
  }
  if (!result) throw new Error('urlscan timed out');

  return {
    scan_metadata: {
      scan_date: result.task?.time || null,
      scan_country: result.page?.country || null,
      screenshot: result.task?.screenshotURL || null,
      report_link: guiLink
    },
    target_info: {
      original_url: target,
      final_url: result.page?.url || null,
      domain: result.page?.domain || null,
      subdomain: result.page?.subdomain || null,
      ip: result.page?.ip || null,
      asn: result.page?.asn || null,
      asnname: result.page?.asnname || null,
      server: result.page?.server || null,
      status_code: result.page?.status || null,
      title: result.page?.title || null
    },
    security_verdicts: {
      malicious: result.verdicts?.overall?.malicious || false,
      risk_score: result.verdicts?.overall?.score || null,
      categories: result.verdicts?.overall?.categories || [],
      tags: result.tags || [],
      summary: result.verdicts?.overall?.description || null
    },
    network_activity: {
      total_requests: result.lists?.requests?.length || 0,
      contacted_hosts: result.lists?.ips || [],
      contacted_domains: result.lists?.domains || [],
      file_types: result.lists?.fileTypes || []
    },
    technologies: result.technologies?.map(t => ({
      name: t.name,
      version: t.version || null,
      categories: t.categories || []
    })) || []
  };
}

module.exports = { urlscanScan };
