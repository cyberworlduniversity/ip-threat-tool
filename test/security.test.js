const test = require('node:test');
const assert = require('node:assert/strict');
const { isPublicIPv4, calculateThreatScore, getRiskLevel } = require('../server');

test('accepts a public IPv4 address', () => {
  assert.equal(isPublicIPv4('8.8.8.8'), true);
});

test('rejects malformed, IPv6, and private IPv4 addresses', () => {
  for (const ip of ['not-an-ip', '2001:4860:4860::8888', '10.0.0.1', '172.16.0.1', '192.168.1.1', '127.0.0.1', '169.254.169.254']) {
    assert.equal(isPublicIPv4(ip), false, ip);
  }
});

test('rejects documentation, multicast, and reserved ranges', () => {
  for (const ip of ['192.0.2.1', '198.51.100.2', '203.0.113.9', '224.0.0.1', '240.0.0.1']) {
    assert.equal(isPublicIPv4(ip), false, ip);
  }
});

test('calculates bounded risk score and risk labels', () => {
  assert.equal(calculateThreatScore({ proxy: true, hosting: true, mobile: true }), 70);
  assert.equal(calculateThreatScore({ proxy: true, hosting: true, mobile: true, org: 'TOR proxy', isp: 'anonymous VPN' }), 100);
  assert.equal(getRiskLevel(10), 'LOW');
  assert.equal(getRiskLevel(50), 'MEDIUM');
  assert.equal(getRiskLevel(80), 'HIGH');
});
