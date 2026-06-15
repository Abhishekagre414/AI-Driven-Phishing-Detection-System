# APDS Frontend (Web Dashboard)

This is the React + Vite frontend for the AI-Driven Phishing Detection System (APDS).

## Getting Started

1. Install dependencies:
   ```bash
   npm install
   ```

2. Run the development server:
   ```bash
   npm run dev
   ```

## Troubleshooting API Connectivity

If you see an **"API Offline"** error while the backend is running, ensure your `vite.config.js` and API calls point to `127.0.0.1` instead of `localhost`. 

Modern Node.js versions (v17+) resolve `localhost` to the IPv6 address `::1`. Since the FastAPI Python backend binds to IPv4 (`127.0.0.1`), the Vite proxy will fail to connect if it's looking for `localhost`. We've set the proxy to `127.0.0.1:8000` to resolve this seamlessly.
