# WEB_GUARD_AI (PhishGuard AI)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-green.svg)](https://nodejs.org/)
[![React Version](https://img.shields.io/badge/React-18-blue.svg)](https://reactjs.org/)
[![Vite](https://img.shields.io/badge/Vite-5.0-646CFF.svg)](https://vitejs.dev/)

WEB_GUARD_AI is a comprehensive cybersecurity platform designed for deep domain intelligence and threat detection. It analyzes URLs against various threat databases, performs heuristic phishing analysis, detects piracy-related content, and provides detailed reconnaissance data including SSL validity, domain age, and hosting intelligence.

## Tech Stack

- **Frontend:** React.js + Vite, Tailwind CSS
- **Backend:** Node.js + Express
- **Database:** MongoDB
- **Security Protocols:** SSL/TLS Inspection, WHOIS Analysis, DNS Resolution, Typosquatting Heuristics

## Project Structure

```text
WEB_GUARD_AI/
├── backend/
│   ├── data/               # Threat intelligence datasets (JSON)
│   ├── models/             # Mongoose database schemas
│   ├── routes/             # Express API endpoints
│   ├── services/           # Backend intelligence & analyzer modules
│   ├── server.js           # Main application entry point
│   └── .env                # Environment configuration (ignored in git)
├── frontend/
│   ├── src/
│   │   ├── components/     # UI Dashboard and Scan components
│   │   ├── services/       # API interaction layer
│   │   └── App.jsx         # Main React entry point
│   ├── package.json        
│   └── vite.config.js      
└── README.md
```

## Installation Guide

Follow these steps to set up the project locally:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/rajeshkannaj7-ai/WEB_GUARD_AI.git
   cd WEB_GUARD_AI
   ```

2. **Backend Setup:**
   ```bash
   cd backend
   npm install
   ```

3. **Frontend Setup:**
   ```bash
   cd ../frontend
   npm install
   ```

## Environment Variables Setup

Create a `.env` file in the `backend/` directory (you can copy `.env.example`):

```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
IPINFO_API_KEY=your_ipinfo_api_key
WHOIS_API_KEY=your_whois_api_key
VT_API_KEY=your_virustotal_api_key
```

## API Keys Setup

To enable full intelligence features, you can obtain API keys from the following providers:

1. **IP Geolocation (IPinfo):**
   - Visit [ipinfo.io](https://ipinfo.io)
   - Create a free account.
   - Copy your access token to `IPINFO_API_KEY`.

2. **Malware Reputation (VirusTotal):**
   - Visit [virustotal.com](https://www.virustotal.com)
   - Register for a free developer account.
   - Go to the API Key section in your profile.
   - Copy the key to `VT_API_KEY`.

3. **WHOIS Lookup (WHOISXMLAPI):**
   - Visit [whoisxmlapi.com](https://www.whoisxmlapi.com)
   - Sign up for a free plan.
   - Locate your API key in the dashboard.
   - Copy the key to `WHOIS_API_KEY`.

## Running Backend Server

Navigate to the backend directory and start the server:

```bash
cd backend
npm start
```

The backend server will run at: `http://localhost:5000`

## Running Frontend Application

Navigate to the frontend directory and start the development server:

```bash
cd frontend
npm run dev
```

The frontend application will run at: `http://localhost:5173`

## Default Ports

| Component | Default URL |
|-----------|-------------|
| Frontend  | http://localhost:5173 |
| Backend   | http://localhost:5000 |
| MongoDB   | mongodb://localhost:27017 |

## Troubleshooting

- **MongoDB Connection Error:** Ensure your MongoDB service is running and the `MONGO_URI` in `.env` is correct.
- **API Failures:** Verify that your API keys are valid and haven't exceeded their free-tier limits.
- **CORS Issues:** The backend is configured to allow requests from `http://localhost:5173`. If you change the frontend port, update the `origin` in `backend/server.js`.

## Author

WEB_GUARD_AI Team
