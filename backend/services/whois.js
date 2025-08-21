// services/whois.js
const { WhoisJson } = require('@whoisjson/whoisjson');
const dns = require('dns').promises;

const whois = new WhoisJson({
  apiKey: process.env.WHOISJSON_API_KEY
});

async function resolveDns(domain) {
  const records = { a: [], aaaa: [], mx: [], ns: [] };

  try {
    records.a = await dns.resolve4(domain);    
  } catch (_) {}

  try {
    records.aaaa = await dns.resolve6(domain);  
  } catch (_) {}

  try {
    records.mx = (await dns.resolveMx(domain)).map(mx => mx.exchange);
  } catch (_) {}

  try {
    records.ns = await dns.resolveNs(domain);
  } catch (_) {}

  return records;
}

async function whoisLookup(domain) {
  try {
    // WHOIS Info
    const whoisInfo = await whois.lookup(domain);
    // DNS Info 
    let dnsInfo = await whois.nslookup(domain);
    if (!dnsInfo?.records || (
        !dnsInfo.records.a && !dnsInfo.records.mx && !dnsInfo.records.ns
    )) {
      dnsInfo = { records: await resolveDns(domain) };
    }
    const sslInfo = await whois.ssl(domain);

    const result = {
      domain: whoisInfo?.name || domain,
      registrar: whoisInfo?.registrar?.name || "N/A",
      status: whoisInfo?.status || [],
      created: whoisInfo?.created || "N/A",
      expires: whoisInfo?.expires || "N/A",
      nameservers: whoisInfo?.nameserver || [],
      country: whoisInfo?.contacts?.owner?.[0]?.country || "N/A",

      dns: {
        a: dnsInfo?.records?.a || [],
        aaaa: dnsInfo?.records?.aaaa || [],
        mx: dnsInfo?.records?.mx || [],
        ns: dnsInfo?.records?.ns || []
      },

      ssl: {
        valid: sslInfo?.valid || false,
        issuer: sslInfo?.issuer?.organization || "N/A",
        validFrom: sslInfo?.validFrom || "N/A",
        validTo: sslInfo?.validTo || "N/A",
        subjectAltNames: sslInfo?.subjectAlternativeNames || []
      }
    };

    return result;
  } catch (error) {
    return { error: error.message };
  }
}

module.exports = { whoisLookup };
