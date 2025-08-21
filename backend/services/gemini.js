// services/gemini.js
const axios = require('axios');

async function geminiSummarize(type, target, analysis) {
  const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
  if (!GEMINI_API_KEY) throw new Error('GEMINI_API_KEY not set');

  const model = "gemini-1.5-flash-latest";
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_API_KEY}`;

  const prompt = `
You are a concise SOC analyst assistant. Given the following scan analysis, produce a short, bullet-point "SOC brief" (4-8 bullets) that highlights:
- Key malicious indicators (what to watch)
- Severity & confidence
- Immediate recommended actions (containment / triage)
- Suggested next investigative steps and useful IOC queries
Do not add speculative facts. Use only the provided data.

TARGET TYPE: ${type}
TARGET: ${target}

ANALYSIS:
${JSON.stringify(analysis, null, 2)}
`;

  try {
    const requestBody = {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.3, maxOutputTokens: 512 }
    };

    const headers = { 'Content-Type': 'application/json' };
    const resp = await axios.post(url, requestBody, { headers, timeout: 25000 });

    let text = resp.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";

    if (!text) {
      return { brief: "Could not extract summary from Gemini response." };
    }
    text = text
      .replace(/\*\*/g, "")     
      .replace(/^[-*•]\s?/gm, ",<br>• ")
      .trim();

    return { brief: text };

  } catch (err) {
    return { brief: `Gemini summarization failed: ${err.message}` };
  }
}

module.exports = { geminiSummarize };