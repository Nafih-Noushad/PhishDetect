# PhishDetect AI

> **AI-Powered Phishing Email Detection System**  
> *Combining Deterministic Heuristic Rules with Local LLM Semantic Reasoning for Explainable Threat Intelligence.*

---

## Overview

**PhishDetect AI** is a full-stack, local-first cybersecurity web application designed to analyze email messages for sophisticated phishing indicators, credential harvesting attempts, and social engineering patterns. 

Traditional signature-based security filters struggle against zero-day spear phishing, while opaque cloud AI APIs pose privacy risks and hallucinate without explainability. PhishDetect AI solves this dilemma using a **dual-engine hybrid architecture**:
1. **Deterministic Rule Engine (0–60 pts)**: Fast, reproducible regular expression and heuristic pattern checks detecting high-risk signals (shortened URLs, IP addresses, credential requests, domain spoofing, urgency cues).
2. **Local AI Reasoning Engine (0–40 pts)**: Runs completely offline using **Ollama** and **Llama 3.2** to evaluate contextual tone, pretexting intent, and semantic coercion without transmitting sensitive email content across the internet.

The system synthesizes these inputs into an explainable **0–100 Risk Score**, categorizes the threat tier (**LOW**, **MEDIUM**, **HIGH**, **CRITICAL**), and presents direct textual evidence and defensive recommendations on an interactive dashboard.

---

## Features

- **Hybrid Detection Pipeline**: Merges 15+ deterministic heuristic checks with local Ollama Llama 3.2 model inference.
- **Explainable Threat Evidence**: Highlights exact quotes, matched indicators, and plain-English reasons for every risk score.
- **Local-First Privacy**: 100% of data processing and LLM inferences occur on the local machine; zero external cloud API dependencies.
- **Interactive Cyberpunk / Dark Glass Dashboard**: Built with responsive HTML5, modern CSS3 custom properties, Lucide icons, and Chart.js telemetry charts.
- **Scan History & Search**: Persistent SQLite storage with full-text search across senders and subjects, risk category filters, sorting, and pagination.
- **Report Exporting**: Export detailed incident response reports in structured JSON or clean, formatted plain-text (TXT) formats.
- **Safe Execution Policy**: Strict non-interactive link inspection—never triggers attacker tracking pixels or downloads malware attachments.
- **Ollama Health Monitor**: Real-time heartbeat checking, model discovery, and connection latency benchmarking.

---

## Technology Stack

| Component | Technology | Rationale |
|---|---|---|
| **Backend** | Python 3.11+ / Flask | Lightweight, robust WSGI framework with clean REST routing and low overhead |
| **Database** | SQLite 3 via SQLAlchemy | Zero-configuration relational persistence, atomic transactions, parameterized queries |
| **Local AI Runtime**| Ollama | High-performance local inference server with REST API support |
| **Default LLM** | Llama 3.2 (3B / 1B) | Superior instruction-following, structured JSON generation, fast local latency |
| **Frontend** | Vanilla HTML5 / CSS3 / ES6 JS | Native performance, accessible contrast, zero bloat, high responsiveness |
| **Charts** | Chart.js v4.4+ | Interactive dark-glass telemetry visualizations |
| **Iconography** | Lucide Icons | Clean, modern cybersecurity iconography |
| **Test Suite** | pytest / pytest-mock | Comprehensive automated unit, integration, and database test coverage |

---

## Architecture

```
+-----------------------------------------------------------------------------------+
|                                  USER BROWSER                                     |
|  [ HTML5 / CSS3 Dark Glass UI ] <---> [ JavaScript Controllers (main, analysis) ] |
+------------------------------------------+----------------------------------------+
                                           | HTTP REST API (JSON)
                                           v
+-----------------------------------------------------------------------------------+
|                               FLASK BACKEND SYSTEM                                |
|                                                                                   |
|  +--------------------+    +----------------------+    +-----------------------+  |
|  | Input Validation   |--->| Rule Engine (0-60pt) |--->| Ollama Service (0-40) |  |
|  | & Sanitization     |    | 15+ Heuristics       |    | Local LLM (Llama 3.2) |  |
|  +--------------------+    +----------------------+    +-----------------------+  |
|                                                                |                  |
|                                                                v                  |
|  +--------------------+    +---------------------------------------------------+  |
|  | SQLite Storage     |<---| Hybrid Risk Synthesizer & Scoring Engine          |  |
|  | History & Settings |    | (Weighted Score: 0-100, Low/Med/High/Critical)    |  |
|  +--------------------+    +---------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## Screenshots

> *Note: Graphical dashboard preview mockups below demonstrate the dark cybersecurity aesthetic.*

### 1. Main Dashboard & Threat Overview
```
+-----------------------------------------------------------------------------------+
|  [🛡️ PhishDetect AI]   [Dashboard]  [Analyze]  [History]  [Analytics]  [Settings]   |
+-----------------------------------------------------------------------------------+
|  [ Total Scans: 142 ]   [ Phishing: 48 ]   [ Safe: 82 ]   [ Critical Threat: 12 ] |
|                                                                                   |
|  [ 7-Day Detection Trend (Line Chart) ]     [ Risk Distribution (Doughnut Chart)] |
|  [ Recent Email Ingestion Stream       ]     [ Ollama Status: Online (Llama 3.2) ] |
+-----------------------------------------------------------------------------------+
```

### 2. Email Inspection & Interactive Results
```
+-----------------------------------------------------------------------------------+
| Email Analysis: security-noreply@paypa1-verify.com                                |
| Subject: URGENT: Your PayPal Account Has Been Suspended - Verify Now!             |
+-----------------------------------------------------------------------------------+
|  RISK GAUGE: [ 96 / 100 ]  CRITICAL THREAT                                        |
|  Breakdown: Rule Points: 60/60  |  AI Reasoning Points: 36/40                    |
|                                                                                   |
|  [!] Heuristic Indicators:                                                        |
|      - CREDENTIAL_REQUEST (+25 pts): Asks for passwords, credit card, and OTP     |
|      - URGENT_LANGUAGE (+15 pts): 'within 24 hours or permanently closed'         |
|      - SUSPICIOUS_URL (+15 pts): Detected URL shortener 'http://bit.ly/paypal'    |
|      - DOMAIN_MISMATCH (+20 pts): PayPal impersonated from 'paypa1-verify.com'    |
|                                                                                   |
|  [🤖 AI Model Verdict]: PHISHING (Confidence: 90%, Uncertainty: 10%)              |
|      Evidence: "Click here to verify your account immediately: http://bit.ly/..."  |
|                                                                                   |
|  [✓ Recommended Next Steps]:                                                      |
|      1. Do not click any links or provide credentials.                            |
|      2. Forward to security operations and report sender.                         |
+-----------------------------------------------------------------------------------+
```

---

## Setup Instructions

### Prerequisites
- **Python**: Version 3.11 or higher installed on your system.
- **Git**: Installed for version control.
- **Ollama**: Installed locally ([Download Ollama](https://ollama.com/download)).

---

### Step 1: Clone or Download the Project
```bash
git clone https://github.com/your-username/phishdetect-ai.git
cd phishdetect-ai
```

---

### Step 2: Create and Activate Python Virtual Environment

**On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Install Dependencies:**
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

### Step 3: Install & Start Ollama
Make sure the Ollama daemon is running in the background.

```bash
ollama serve
```

---

### Step 4: Download the AI Model
Pull the recommended lightweight **Llama 3.2** model:

```bash
ollama pull llama3.2
```

*(Optional: If your system has limited GPU/RAM, you can also use `ollama pull llama3.2:1b` or `phi3:mini` and configure it in Settings).*

---

### Step 5: Configure Environment
Copy the example environment configuration:

```bash
copy .env.example .env     # Windows
# or
cp .env.example .env        # Linux / macOS
```

*(Default settings connect to `http://127.0.0.1:11434` with `llama3.2` and use a local SQLite database).*

---

### Step 6: Initialize & Run the Application
```bash
python run.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

### Step 7: Administrative Login
To access settings, history administration, and scan management:
- **Email**: `admin@phishdetect.ai`
- **Password**: `admin123`

---

## Running Automated Tests

Run the complete pytest test suite with verbose reporting:

```bash
python -m pytest tests/ -v
```

### Test Suite Structure:
- `tests/test_detection.py`: 12 test cases verifying all deterministic heuristic rules, caps detection, URL parsing, and the 60-point score cap.
- `tests/test_scoring.py`: 12 test cases verifying category bands (LOW/MED/HIGH/CRIT), confidence scaling, score clamping, and score report generation.
- `tests/test_ollama.py`: 10 test cases verifying Ollama connection handling, timeouts, model discovery, and Markdown JSON extraction.
- `tests/test_database.py`: 12 test cases using in-memory SQLite (`:memory:`) verifying scan persistence, search filtering, pagination, SQL injection prevention, and cascading deletes.

```bash
# Run specific test modules:
python -m pytest tests/test_detection.py -v
python -m pytest tests/test_scoring.py -v
python -m pytest tests/test_ollama.py -v
python -m pytest tests/test_database.py -v
```

---

## Usage Guide

1. **Email Inspection Screen**:
   - Paste sender address, subject line, and body text.
   - Use the **Try Phishing Example** button to instantly load an authentic credential harvesting attack sample.
   - Use the **Try Legit Example** button to test against a benign GitHub notification.
   - Click **Inspect Email** to initiate the multi-step scanning pipeline.

2. **Results View**:
   - Inspect the interactive circular SVG risk meter.
   - Review each deterministic rule triggered and its exact evidence snippet.
   - Inspect the AI verdict, confidence rating, and semantic threat reasoning.
   - Click **Copy Report** to copy the full technical JSON findings to your clipboard.
   - Click **Export JSON** or **Export TXT** to download persistent incident reports.

3. **History Management**:
   - Search historical scans by sender email or subject keywords.
   - Filter scans by threat tier (LOW, MEDIUM, HIGH, CRITICAL).
   - Delete individual scans or use **Clear All** with confirmation protection.

4. **Analytics Telemetry**:
   - View real-time security KPI telemetry (total analyzed, phishing rate %, safe rate %, critical count).
   - Review the 7-day scan volume line chart and the heuristic indicator frequency table.

5. **Settings & Ollama Configuration**:
   - Change Ollama API base URL or select alternative installed models dynamically.
   - Test Ollama connection health and observe round-trip latency in milliseconds.

---

## API Reference

| Endpoint | Method | Input | Output | Purpose |
|---|---|---|---|---|
| `/api/stats` | `GET` | None | `{total_scans, phishing_count, safe_count, ...}` | Global metrics for dashboard counters |
| `/api/analyze` | `POST` | `{"sender", "subject", "body"}` | Full scan JSON with score & findings | Runs heuristic + AI pipeline |
| `/api/scan/<id>` | `GET` | None | Full scan details | Retrieves a single saved scan report |
| `/api/history` | `GET` | Query params: `page`, `search`, `category`, `sort_by` | `{scans, total, page, pages}` | Paginated, filtered historical records |
| `/api/history/<id>`| `DELETE` | None | `{"success": true}` | Deletes a single scan record |
| `/api/history` | `DELETE` | None | `{"success": true, "deleted": N}` | Wipes all historical scan records |
| `/api/analytics` | `GET` | None | Chart telemetry datasets & KPIs | Supplies data for all 4 dashboard charts |
| `/api/settings` | `GET/POST`| Settings payload | Active configuration object | Manages Ollama connection parameters |
| `/api/ollama/status`| `GET` | None | `{connected, current_model, error}` | Real-time Ollama daemon health |
| `/api/ollama/test` | `POST` | `{"url": "..."}` | `{success, response_time_ms}` | Benchmarks connection latency |
| `/api/export/<id>` | `GET` | Query param: `format=json\|txt` | Downloadable attachment file | Exports incident report |

---

## Risk Scoring Explanation

$$\text{Final Risk Score} = \min(100, \max(0, \text{Rule Score (0–60)} + \text{AI Score (0–40)}))$$

### Risk Category Thresholds:
- **LOW (0–24)**: Standard legitimate correspondence. No suspicious indicators detected.
- **MEDIUM (25–49)**: Suspicious signals detected (e.g., external links or urgent language). Proceed with caution.
- **HIGH (50–74)**: Strong probability of phishing or social engineering. Do not click links or reply.
- **CRITICAL (75–100)**: Severe confirmed phishing or credential harvesting attack. Immediate containment recommended.

### Difference Between Risk Score & Model Confidence:
- **Risk Score (0–100)**: A measure of the overall danger and severity of the email based on combined heuristic evidence and AI findings.
- **Model Confidence (0.0–1.0)**: A statistical measure of how certain the LLM is regarding its specific verdict (`PHISHING`, `SUSPICIOUS`, `LEGITIMATE`). A high confidence verdict of `LEGITIMATE` results in a **low** risk score.

---

## Limitations & Ethical Disclaimer

1. **Advisory Purpose Only**: PhishDetect AI is designed as an educational and diagnostic tool for security analysts and students. It does not replace enterprise-grade Secure Email Gateways (SEGs).
2. **False Positives / False Negatives**: Benign marketing emails utilizing urgent promotional deadlines may be flagged as suspicious. Sophisticated spear-phishing attacks utilizing brand-new domains without known signatures may require manual analyst review.
3. **No Automatic Network Actions**: The software never automatically downloads attachments or resolves suspicious hyperlinks to prevent drive-by malware infections or triggering threat actor telemetry.
4. **Data Privacy**: Local LLMs protect privacy from third-party cloud providers, but users must ensure that host machine storage and local logs are secured appropriately.

---

## License

This project is released under the **MIT License**. Feel free to use, modify, and distribute for academic and professional security research.
