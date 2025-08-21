// services/abuseipdb.js
const axios = require('axios');

const abuseCategoryMap = {
  3: "Fraud Orders",
  4: "DDoS Attack",
  5: "FTP Brute-Force",
  6: "Ping of Death",
  7: "Phishing",
  8: "Fraud VOIP",
  9: "Open Proxy",
  10: "Web Spam",
  11: "Email Spam",
  12: "Blog Spam",
  13: "VPN IP",
  14: "Port Scan",
  15: "Hacking",
  16: "SQL Injection",
  17: "Spoofing",
  18: "Brute-Force",
  19: "Bad Web Bot",
  20: "Exploited Host",
  21: "Web App Attack",
  22: "SSH Brute-Force",
  23: "IoT Targeted"
};

async function abuseLookup(ip) {
  const ABUSEIP_API_KEY = process.env.ABUSEIP_API_KEY;
  if (!ABUSEIP_API_KEY) throw new Error('ABUSEIP_API_KEY not set');

  const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
    params: { ipAddress: ip, maxAgeInDays: 90, verbose: true },
    headers: { Key: ABUSEIP_API_KEY, Accept: 'application/json' }
  });

  const data = response.data.data;

  let categories = [];
  if (data.reports && Array.isArray(data.reports)) {
    const catCount = {};
    data.reports.forEach(report => {
      if (report.categories) {
        report.categories.forEach(cat => { catCount[cat] = (catCount[cat] || 0) + 1; });
      }
    });
    categories = Object.entries(catCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([catId]) => abuseCategoryMap[catId] || `Category ${catId}`);
  }

  return {
    ip: data.ipAddress,
    domain: data.domain || null,
    country: data.countryCode || null,
    asn: data.asn || null,
    isp: data.isp || null,
    usageType: data.usageType || null,
    totalReports: data.totalReports,
    abuseConfidenceScore: data.abuseConfidenceScore,
    lastReportedAt: data.lastReportedAt,
    commonCategories: categories,
    directLink: `https://www.abuseipdb.com/check/${data.ipAddress}`
  };
}

module.exports = { abuseLookup };
