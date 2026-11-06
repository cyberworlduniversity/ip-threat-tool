const express = require('express');
const path = require('path');
const net = require('node:net');

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.disable('x-powered-by');
app.use(express.json({ limit: '16kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const IPV4_BLOCKED = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10],
  ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

function ipv4ToNumber(address) {
  return address.split('.').reduce((value, part) => ((value << 8) | Number(part)) >>> 0, 0);
}

function inSubnet(address, subnet, prefix) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4ToNumber(address) & mask) === (ipv4ToNumber(subnet) & mask);
}

function isPublicIPv4(value) {
  if (net.isIP(value) !== 4) return false;
  return !IPV4_BLOCKED.some(([subnet, prefix]) => inSubnet(value, subnet, prefix));
}

function calculateThreatScore(data) {
  let score = 0;
  if (data.proxy) score += 40;
  if (data.hosting) score += 25;
  if (data.mobile) score += 5;
  if (data.org && /vpn|proxy|tor|anonymous/i.test(data.org)) score += 30;
  if (data.isp && /vpn|proxy|anonymous/i.test(data.isp)) score += 20;
  return Math.min(score, 100);
}

function getRiskLevel(score) {
  if (score >= 70) return 'HIGH';
  if (score >= 35) return 'MEDIUM';
  return 'LOW';
}

app.get('/api/lookup/:ip', async (req, res) => {
  const ip = req.params.ip;
  if (!isPublicIPv4(ip)) {
    return res.status(400).json({ error: 'Enter a valid public IPv4 address.' });
  }

  try {
    const endpoint = new URL(`https://ipwho.is/${encodeURIComponent(ip)}`);
    const response = await fetch(endpoint, { signal: AbortSignal.timeout(8000) });
    if (!response.ok) {
      return res.status(502).json({ error: 'IP intelligence provider is unavailable.' });
    }
    const providerData = await response.json();
    if (providerData.success !== true) {
      return res.status(502).json({ error: 'IP intelligence lookup failed.' });
    }

    const connection = providerData.connection || {};
    const security = providerData.security || {};
    const timezone = providerData.timezone || {};
    const data = {
      query: providerData.ip || ip,
      country: providerData.country,
      countryCode: providerData.country_code,
      regionName: providerData.region,
      city: providerData.city,
      zip: providerData.postal,
      lat: providerData.latitude,
      lon: providerData.longitude,
      timezone: timezone.id,
      isp: connection.isp,
      org: connection.org,
      as: connection.asn,
      reverse: providerData.connection?.domain,
      mobile: Boolean(security.mobile),
      proxy: Boolean(security.proxy || security.vpn || security.tor),
      hosting: Boolean(security.hosting),
    };
    data.threatScore = calculateThreatScore(data);
    data.riskLevel = getRiskLevel(data.threatScore);
    res.set('Cache-Control', 'no-store');
    return res.json(data);
  } catch (err) {
    const timedOut = err && (err.name === 'TimeoutError' || err.name === 'AbortError');
    return res.status(timedOut ? 504 : 502).json({
      error: timedOut ? 'IP intelligence lookup timed out.' : 'Failed to fetch IP intelligence.',
    });
  }
});

// Do not trust arbitrary X-Forwarded-For headers. Configure Express trust proxy
// explicitly at deployment if the app is behind a known trusted proxy.
app.get('/api/myip', (req, res) => {
  const ip = (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
  if (!ip || net.isIP(ip) === 0) {
    return res.status(503).json({ error: 'Client IP address is unavailable.' });
  }
  res.set('Cache-Control', 'no-store');
  return res.json({ ip });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`IP Threat Intelligence Tool listening on port ${PORT}`));
}

module.exports = { app, isPublicIPv4, calculateThreatScore, getRiskLevel };
