# PhishDetect AI — System Architecture & Technical Specifications

**PhishDetect AI** is an explainable, hybrid phishing email detection system that fuses deterministic heuristic pattern recognition with local large language model (LLM) semantic reasoning using **Ollama**.

---

## 1. System Overview Diagram

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

## 2. Component Descriptions

### 2.1 Frontend Web Client
- **Tech Stack**: Vanilla HTML5, modern CSS3 (custom CSS custom properties, responsive grid/flexbox, dark-mode cybersecurity palette), JavaScript (ES6+ modular controllers), Chart.js (v4), and Lucide Icons.
- **Responsibilities**:
  - Securely collects sender, subject, and email body with client-side character validation and trimming.
  - Displays multi-step animated scanning pipeline during asynchronous analysis.
  - Dynamically renders interactive SVG score gauges, category risk badges, heuristic indicator finding cards, AI evidence snippets, and next-step recommendations.
  - Manages search, category filtering, pagination, and deletion of historical scans.
  - Visualizes real-time security telemetry (daily scan distribution, detection trends, and top indicator charts).

### 2.2 Flask Backend API Server
- **Tech Stack**: Python 3.11+, Flask REST architecture, SQLAlchemy ORM.
- **Responsibilities**:
  - Serves dynamic UI views and exposes secure JSON REST endpoints.
  - Validates and normalizes all incoming payloads (email formats, payload limits, type safety).
  - Orchestrates execution order between deterministic rule checks and asynchronous LLM inferences.
  - Manages session authentication and authorization.
  - Persists analysis records and generates report exports (JSON and formatted TXT).

### 2.3 Deterministic Rule-Based Detection Engine (`PhishingDetectionEngine`)
- **Tech Stack**: Pure Python, compiled regular expressions (`re`), URI parsers (`urllib.parse`).
- **Characteristics**: Deterministic, transparent, zero-network-dependency, reproducible.
- **Inspects**:
  1. **Suspicious URLs**: IP-based links (e.g. `http://192.168.1.1/login`), URL shorteners (`bit.ly`, `tinyurl`, `t.co`), punycode/lookalike characters, non-standard ports.
  2. **Urgency & Coercion**: Artificial countdowns, immediate account suspension threats, legal penalties, panic-inducing calls to action.
  3. **Credential & Sensitive Data Harvesting**: Solicitations for passwords, PINs, OTP codes, credit card numbers, social security IDs.
  4. **Brand & Domain Mismatch**: Sender display name claims to be PayPal, Chase, Microsoft, or Google, but originating domain does not match authentic MX domains.
  5. **Malicious Attachments**: References to compressed archives (`.zip`, `.rar`, `.7z`), executables (`.exe`, `.scr`, `.bat`), or macro-enabled documents (`.xlsm`).
  6. **Excessive Capitalization**: High percentage of uppercase words designed to manipulate cognitive arousal.
- **Scoring**: Allocates up to **60 points** across documented findings, strictly capped to prevent heuristic score inflation.

### 2.4 Ollama Local AI Service (`OllamaService`)
- **Tech Stack**: Local HTTP API connection (`http://127.0.0.1:11434`), default model: **Llama 3.2** (3B / 1B).
- **Responsibilities**:
  - Performs semantic, contextual, and intent reasoning beyond regex matching (detecting subtle social engineering, pretexting, spear phishing).
  - Enforces structured JSON output schema containing:
    - `verdict`: `PHISHING` | `SUSPICIOUS` | `LEGITIMATE`
    - `confidence`: Float `0.0` to `1.0`
    - `uncertainty`: Float `0.0` to `1.0`
    - `reasons`: List of plain-English analytical explanations
    - `evidence`: Direct verbatim quotes from email text
    - `recommended_actions`: Actionable mitigation steps
  - Robust error handling: Handles daemon offline status, request timeouts (30s), non-JSON response stripping, and Markdown code block extraction.

### 2.5 Hybrid Risk Scoring Synthesizer (`risk_scoring`)
- Combines rule points (0–60) and AI points (0–40) into a single explainable 0–100 risk score.
- Categorizes risk into four standardized security tiers: **LOW**, **MEDIUM**, **HIGH**, **CRITICAL**.
- Emphasizes explainability: every point gained is traceable to an indicator or LLM confidence score.

### 2.6 Persistence Layer (SQLite & SQLAlchemy)
- Embedded relational database storing scan records, detailed indicator findings, and system configuration.
- Utilizes parameterized queries across all operations to eliminate SQL injection vulnerabilities.
- Foreign key constraints ensure cascading deletion when scans are purged.

---

## 3. End-to-End Data Flow

```
1. Input Submission
   [User] ──(Sender, Subject, Body)──> [Web Client] ──(POST /api/analyze)──> [Flask API]
                                                                                  │
2. Normalization & Validation                                                     │
   Validate email structure, trim whitespace, check max 50KB length              │
                                                                                  │
3. Parallel / Sequential Processing Pipeline                                      │
   ├──> [Deterministic Rule Engine] ──────────────────────────┐                   │
   │    Scans text for URLs, urgency, credential harvesting    │                   │
   │    Produces: Rule Findings List + Rule Score (0-60)      │                   │
   │                                                          │                   │
   └──> [Ollama Local AI (Llama 3.2)] ────────────────────────┼───────────────────┘
        Evaluates contextual intent & semantic manipulation   │
        Produces: AI Verdict, Confidence, Evidence (0-40)     │
                                                              v
4. Risk Synthesis & Scoring
   Combined Score = Clamp(Rule Score + AI Score, 0, 100)
   Category = LOW (0-24) | MEDIUM (25-49) | HIGH (50-74) | CRITICAL (75-100)
                                │
5. Persistence                  v
   Write to SQLite: Scans Table + Findings Table (Foreign Key Linked)
                                │
6. Response Rendering           v
   Return JSON to Frontend ──> Render SVG Gauge, Finding Cards, Advice ──> [User]
```

---

## 4. API Reference Table

| Method | Endpoint | Description | Request Body | Response Format |
|---|---|---|---|---|
| `POST` | `/api/login` | Authenticate administrative user | `{"email": str, "password": str}` | `{"success": bool, "message": str}` |
| `GET` | `/api/logout` | Terminate session | None | Redirect `/login` |
| `GET` | `/api/stats` | Global dashboard telemetry | None | `{"total_scans": int, "phishing_count": int, "safe_count": int, "critical_count": int, "recent_scans": list}` |
| `POST` | `/api/analyze` | Run email phishing analysis | `{"sender": str, "subject": str, "body": str}` | `{"success": bool, "scan_id": str, "risk_score": int, "risk_category": str, "rule_score": int, "ai_score": int, ...}` |
| `GET` | `/api/scan/<id>` | Fetch complete scan record | None | `{"success": bool, "scan": object}` |
| `GET` | `/api/history` | Paginated & filtered scans | Query params: `page`, `per_page`, `search`, `category`, `sort_by`, `sort_dir` | `{"scans": list, "total": int, "page": int, "per_page": int, "pages": int}` |
| `DELETE`| `/api/history/<id>` | Delete single scan | None | `{"success": bool, "message": str}` |
| `DELETE`| `/api/history` | Clear all scan history | None | `{"success": bool, "deleted": int}` |
| `GET` | `/api/analytics` | Telemetry & chart datasets | None | `{"daily_activity": list, "category_distribution": dict, "top_indicators": list, "weekly_trend": list, "kpis": dict}` |
| `GET` | `/api/settings` | Retrieve active settings | None | `{"ollama_url": str, "ollama_model": str, "app_version": str, "db_path": str, "total_scans": int}` |
| `POST` | `/api/settings` | Save application settings | `{"ollama_url": str, "ollama_model": str}` | `{"success": bool, "message": str}` |
| `GET` | `/api/ollama/status` | Check Ollama service health | None | `{"connected": bool, "error": str, "models": list, "current_model": str}` |
| `GET` | `/api/ollama/models` | List available models | None | `{"models": [str]}` |
| `POST` | `/api/ollama/test` | Test Ollama handshake & latency | Optional `{"url": str}` | `{"success": bool, "message": str, "response_time_ms": int}` |
| `GET` | `/api/export/<id>` | Download report (JSON or TXT) | Query param: `format=json\|txt` | File Attachment Download |

---

## 5. Database Schema

The database is built on **SQLite 3** managed via **SQLAlchemy**.

```
+------------------------------------+          +------------------------------------+
|               scans                |          |              findings              |
+------------------------------------+          +------------------------------------+
| scan_id (PK, VARCHAR(36))          |<---1:N---| id (PK, INTEGER AUTOINCREMENT)     |
| sender (VARCHAR(255))              |          | scan_id (FK -> scans.scan_id)      |
| subject (VARCHAR(500))             |          | indicator_type (VARCHAR(64))       |
| body_snippet (TEXT)                |          | description (TEXT)                 |
| risk_score (INTEGER)               |          | points (INTEGER)                   |
| risk_category (VARCHAR(20))        |          | evidence_json (TEXT)               |
| rule_score (INTEGER)               |          +------------------------------------+
| ai_score (INTEGER)                 |
| ai_verdict (VARCHAR(20))           |          +------------------------------------+
| ai_confidence (FLOAT)              |          |              settings              |
| ai_uncertainty (FLOAT)             |          +------------------------------------+
| ai_reasons_json (TEXT)             |          | key (PK, VARCHAR(64))              |
| ai_evidence_json (TEXT)            |          | value (TEXT)                       |
| ai_actions_json (TEXT)             |          | updated_at (DATETIME)              |
| model_used (VARCHAR(64))           |          +------------------------------------+
| scan_timestamp (DATETIME)          |
+------------------------------------+
```

### Table Details:
1. **`scans`**: Master table for each email inspection event.
   - `scan_id`: UUID4 primary key string.
   - `risk_score`: Consolidated 0–100 integer.
   - `risk_category`: Categorical string (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
   - `scan_timestamp`: UTC datetime, indexed for fast chronological queries.
2. **`findings`**: Detailed heuristic indicators flagged for each scan.
   - Foreign key `scan_id` has `ON DELETE CASCADE` enabled.
   - `points`: Integer risk weight contributed by this indicator.
3. **`settings`**: Key-value pair configuration table for runtime parameters (e.g. `ollama_url`, `ollama_model`).

---

## 6. Security, Privacy & Safety Considerations

### 6.1 Local-First Privacy (No Data Transmission)
- AI inference runs **100% locally** via Ollama on the user's host machine.
- Email contents, headers, and credentials tested are **never transmitted** to external cloud APIs (e.g. OpenAI, Anthropic), preventing proprietary data leakage and complying with GDPR/HIPAA privacy principles.

### 6.2 Strict No-Link-Clicking Safety Policy
- PhishDetect AI **never** opens, pings, curls, or executes links found in emails.
- URLs are parsed syntactically using regular expressions and domain decomposition to avoid triggering attacker canary tokens or drive-by downloads.

### 6.3 Defense Against SQL Injection
- All database interactions use SQLAlchemy ORM or parameterized prepared statements (`?` binding in SQLite).
- No raw string interpolation or string formatting is ever permitted in SQL queries.

### 6.4 Cross-Site Scripting (XSS) Prevention
- User input rendered into DOM is escaped via HTML entity sanitization (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#039;`).
- Jinja2 auto-escaping is strictly enabled on all server-rendered templates.

### 6.5 Prompt Injection & LLM Guardrails
- Email body text passed to the local LLM prompt is encapsulated in strict delimiter fences.
- System instructions explicitly direct the model to treat email text solely as untrusted data to analyze, preventing jailbreaks or instruction overrides.

---

## 7. Scoring Algorithm Explanation

The risk score is formulated as a transparent hybrid model combining **deterministic heuristics** with **probabilistic AI reasoning**:

$$\text{Final Risk Score} = \min(100, \max(0, \text{Rule Score} + \text{AI Score}))$$

### 7.1 Rule Score (0–60 Points Maximum)
Each triggered heuristic rule contributes a predefined severity weight:

| Indicator Code | Heuristic Check | Severity Points |
|---|---|---|
| `CREDENTIAL_REQUEST` | Solicits passwords, OTP, PIN, credit card data | +25 pts |
| `URGENT_LANGUAGE` | Coercive urgency, 24-hr threats, legal intimidation | +15 pts |
| `SUSPICIOUS_URL` | IP address host, URL shortener, lookalike domain | +15 pts |
| `DOMAIN_MISMATCH` | Known brand claimed in text/from name vs sender domain | +20 pts |
| `SUSPICIOUS_ATTACHMENT` | References executable or archived payloads (.zip, .exe) | +15 pts |
| `EXCESSIVE_CAPS` | Excessive uppercase shouting words | +10 pts |

*Rule Score is capped at 60 points max to ensure the deterministic signal does not monopolize the final score.*

### 7.2 AI Assessment Score (0–40 Points Maximum)
The AI model outputs a discrete verdict and a continuous confidence score $C \in [0.0, 1.0]$:

$$\text{AI Score} = \begin{cases} 
40 \times C & \text{if Verdict} = \text{PHISHING} \\
25 \times C & \text{if Verdict} = \text{SUSPICIOUS} \\
0 & \text{if Verdict} = \text{LEGITIMATE}
\end{cases}$$

### 7.3 Category Thresholds
- **LOW (0–24)**: Standard legitimate correspondence. No actionable threat identified.
- **MEDIUM (25–49)**: Suspicious signals detected (e.g., urgency or external link). Proceed with caution.
- **HIGH (50–74)**: Strong indicators of phishing or social engineering. Do not click links or reply.
- **CRITICAL (75–100)**: Severe confirmed phishing or credential harvesting attack. Immediate containment recommended.

### 7.4 Worked Example
- **Scenario**: Email impersonating PayPal asking for password verification within 24 hours with a `bit.ly` link.
  - Heuristic Checks:
    - Urgency Detected: +15 pts
    - Credential Request: +25 pts
    - Suspicious Shortened URL: +15 pts
    - Domain Mismatch: +20 pts
    - *Raw Rule Sum*: 75 pts $\rightarrow$ **Capped Rule Score = 60 pts**
  - AI Assessment:
    - Verdict: `PHISHING`, Confidence: $0.90$
    - *AI Score*: $40 \times 0.90 = 36 \text{ pts}$
  - **Final Score**: $\min(100, 60 + 36) = \mathbf{96 \text{ / } 100}$
  - **Category**: **CRITICAL**
