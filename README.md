# AI-Driven Phishing Detection System (APDS)

The **AI-Driven Phishing Detection System (APDS)** is an advanced, real-time threat intelligence pipeline designed to scan, score, and triage raw email content. By combining multiple detection strategies—header forensics, linguistic intent analysis (NLP), and URL risk assessment—APDS provides actionable insights and explainable threat scoring via SHAP.

![Simulation Fallback](frontend/public/icons.svg)

## System Architecture

The scoring pipeline operates through a late-fusion decision engine:

1. **Email Parser**: Extracts routing hops, headers (DMARC/SPF/DKIM), and plain-text body.
2. **Header Forensics**: Validates domains, sender impersonation, and routing security.
3. **NLP Semantic Analyzer**: Detects urgency, credential harvesting, and Business Email Compromise (BEC) intent.
4. **URL Risk Scorer**: Analyzes embedded links for typosquatting, brand impersonation, and domain age.
5. **Fusion Engine**: Combines indicators into an explainable confidence score.

## Directory Structure

* `/backend` - FastAPI scoring engine, REST endpoints, and NLP inference code.
* `/frontend` - React & Vite SPA dashboard for Security Operation Center (SOC) analysts.
* `/ml` - Threat fusion algorithms and machine learning logic.
* `/security` - Email parsing, forensic extraction, and URL analysis logic.

## Getting Started

### 1. Run the Backend API
The backend requires Python 3.14+ and its dependencies.
```bash
pip install -r requirements.txt
python -m uvicorn backend.main:app --reload --port 8000
```
*Note: Make sure your Python environment has the necessary build tools to compile dependencies if pre-built wheels aren't available.*

### 2. Run the Frontend Dashboard
The frontend is built with React and Vite. It connects to the backend API locally.
```bash
cd frontend
npm install
npm run dev
```

## Troubleshooting API Connectivity
If the frontend UI shows an **"API Offline"** error while the backend is running, ensure you are not encountering IPv6 proxy resolution issues:
* Modern Node.js versions resolve `localhost` to `::1` (IPv6), but `uvicorn` binds to `127.0.0.1` (IPv4).
* The `vite.config.js` proxy has been explicitly configured to target `http://127.0.0.1:8000` to prevent `ECONNREFUSED` connection errors.

For more detailed technical insights, check out the [Walkthrough Document](walkthrough.md).
