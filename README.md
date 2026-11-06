# 🛡 IP Threat Intelligence Tool


## Get this repository

Clone the current project (this repository's canonical GitHub URL), then follow the installation and usage steps below.

```bash
git clone https://github.com/cyberworlduniversity/ip-threat-tool.git
cd ip-threat-tool
```

A sleek, cyberpunk-styled web application for analyzing IP addresses — built with Node.js and Express.

## ✨ Features

- **IP Lookup** — Enter any IPv4 address to get instant intel
- **My IP** — One-click detection of your own public IP
- **Geolocation Data** — Country, region, city, timezone, ZIP code, ISP, ASN
- **Threat Assessment** — Proxy detection, VPN/hosting flags, threat score (0–100)
- **Risk Level Indicator** — LOW / MEDIUM / HIGH with animated threat bar
- **Map View** — Interactive Leaflet.js map pinning the IP's location
- **JSON Viewer** — Collapsible raw JSON response with syntax highlighting & copy button

## 🚀 Quick Start

### Prerequisites
- Node.js v18 or higher
- npm

### Install & Run

```bash
# 1. Install dependencies
npm install

# 2. Start the server
npm start
```

Then open your browser at: **http://localhost:3000**

### Development Mode (auto-restart)

```bash
npm run dev
```

## 📁 Project Structure

```
ip-threat-tool/
├── server.js          # Express backend + IP lookup API
├── package.json       # Dependencies & scripts
├── README.md          # This file
└── public/
    └── index.html     # Full frontend (HTML + CSS + JS)
```

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/lookup/:ip` | Analyze an IP address |
| GET | `/api/myip` | Get the requester's IP |

### Example Response

```json
{
  "query": "8.8.8.8",
  "country": "United States",
  "countryCode": "US",
  "city": "Mountain View",
  "isp": "Google LLC",
  "proxy": false,
  "hosting": true,
  "threatScore": 25,
  "riskLevel": "LOW"
}
```

## 🌐 Data Sources

- **[ip-api.com](http://ip-api.com)** — Free geolocation & proxy detection API (no key required)
- **[OpenStreetMap](https://openstreetmap.org)** — Free map tiles via Leaflet.js

## ⚠️ Disclaimer

This tool is for educational and informational purposes only. Use responsibly and ethically.

## 👤 Author

**hemanathan115**

## 📄 License

MIT License
