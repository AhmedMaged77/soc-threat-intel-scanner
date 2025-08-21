// services/vt.js
const axios = require('axios');

function humanFileSize(bytes) {
  if (!bytes && bytes !== 0) return null;
  const thresh = 1024;
  if (Math.abs(bytes) < thresh) return bytes + ' B';
  const units = ['KB','MB','GB','TB','PB','EB','ZB','YB'];
  let u = -1;
  do {
    bytes /= thresh;
    ++u;
  } while (Math.abs(bytes) >= thresh && u < units.length - 1);
  return bytes.toFixed(2) + ' ' + units[u];
}

async function vtLookup(type, target) {
  const VT_API_KEY = process.env.VT_API_KEY;
  if (!VT_API_KEY) throw new Error('VT_API_KEY not set');

  let endpoint = '';
  let vtLink = '';
  const encoded = encodeURIComponent(target);

  if (type === 'url') {
    const urlId = Buffer.from(target).toString('base64').replace(/=+$/, '');
    endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    vtLink = `https://www.virustotal.com/gui/url/${urlId}`;
  } else if (type === 'ip') {
    endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encoded}`;
    vtLink = `https://www.virustotal.com/gui/ip-address/${target}`;
  } else if (type === 'file' || type === 'hash') {
    endpoint = `https://www.virustotal.com/api/v3/files/${encoded}`;
    vtLink = `https://www.virustotal.com/gui/file/${target}`;
  } else if (type === 'domain') {
    endpoint = `https://www.virustotal.com/api/v3/domains/${encoded}`;
    vtLink = `https://www.virustotal.com/gui/domain/${target}`;
  } else {
    throw new Error('Unsupported VT lookup type');
  }

  const resp = await axios.get(endpoint, { headers: { 'x-apikey': VT_API_KEY } });
  const data = resp.data?.data || {};
  const attrs = data.attributes || {};

  const lastResults = attrs.last_analysis_results || {};
  const maliciousEngines = Object.entries(lastResults)
    .filter(([engine, info]) => {
      const cat = (info && info.category) ? info.category.toLowerCase() : '';
      return cat === 'malicious' || cat === 'suspicious' || (info.result && info.result.toLowerCase() !== 'clean');
    })
    .map(([engine, info]) => ({
      engine,
      category: info.category || null,
      result: info.result || null,
      method: info.method || null,
      engine_update: info.engine_update || null
    }));

  const meta = {};
  if (type === 'file' || type === 'hash') {
    const namesArr = Array.isArray(attrs.names) ? attrs.names : (attrs.names ? [attrs.names] : []);
    meta.file_names = namesArr.length ? namesArr : null;
    meta.file_name = namesArr.length ? namesArr[0] : null;
    meta.file_size = attrs.size ?? null;
    meta.file_size_readable = attrs.size != null ? humanFileSize(attrs.size) : null;
    meta.type_description = attrs.type_description || null;
    meta.mime_type = attrs.mime_type || null;
    meta.pe_info = {};
    if (attrs.pe_info) {
      meta.pe_info.imphash = attrs.pe_info.imphash || null;
      meta.pe_info.imports_count = Array.isArray(attrs.pe_info.imports) ? attrs.pe_info.imports.length : null;
      meta.pe_info.exports_count = Array.isArray(attrs.pe_info.exports) ? attrs.pe_info.exports.length : null;
    } else {
      meta.pe_info = null;
    }
    meta.first_submission_date = attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toISOString() : null;
    meta.last_submission_date = attrs.last_submission_date ? new Date(attrs.last_submission_date * 1000).toISOString() : null;
    meta.popular_threat_classification = attrs.popular_threat_classification || null;
  } else if (type === 'url') {
    meta.final_url = attrs.last_final_url || null;
  } else if (type === 'domain' || type === 'ip') {
    meta.resolutions = attrs.resolutions || attrs.last_dns_records || null;
    meta.whois = attrs.whois || null;
  }

  return {
    raw_type: data.type || type,
    vt_link: vtLink,
    last_analysis_stats: attrs.last_analysis_stats || {},
    last_analysis_date: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
    reputation: attrs.reputation ?? null,
    tags: attrs.tags || [],
    popular_threat_classification: attrs.popular_threat_classification || null,
    malicious_engines: maliciousEngines,
    total_malicious: maliciousEngines.length,
    meta: meta
  };
}

module.exports = { vtLookup };
