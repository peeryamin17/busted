# BugSeek AI 🛡️

> **Autonomous AI-Powered Security Reconnaissance & Multi-Agent Swarm Platform**  
> Client-side Manifest V3 Chrome Extension paired with an enterprise-grade Security Ontology, Inter-Procedural SAST Taint Engine, and Fastify / PostgreSQL multi-agent backend.

---

## ⚡ What is BugSeek AI?

BugSeek AI bridges the gap between passive browser security inspection and deep, autonomous active testing. Built specifically for bug bounty hunters, application security engineers, and red teams:

1. **Client-Side Reconnaissance (Zero Backend Required)**:
   - **SPA Route & Bundle Extractor**: Parses same-origin JavaScript chunks in memory, carving out hidden API paths (`/api/...`, `/rest/...`), Angular/React/Vue client-side routes, and parameterized endpoints without executing hostile code.
   - **Inter-Procedural SAST Taint Engine**: Parses JavaScript ASTs via Acorn, tracks untrusted input sources (`location.search`, `hash`, `document.referrer`) to dangerous DOM sinks (`innerHTML`, `eval`, `document.write`), models function transfer summaries across scope boundaries, and enforces alpha-beta sanitizer pruning (`encodeURIComponent`, `DOMPurify.sanitize`).
   - **Passive Audits**: Automated checks for security headers (CSP, HSTS, X-Frame-Options), cookie security (`HttpOnly`, `Secure`, `SameSite`), hardcoded credentials/API keys (AWS, Stripe, Supabase, OpenAI, private keys), tech stack fingerprinting, and DOM XSS injection sinks.
   - **Zero-Friction BYOK**: Paste your Google Gemini API key (`AIza...`) directly into the popup settings for instant local unlock without backend dependency.

2. **Autonomous Multi-Agent AI Swarm (Backend)**:
   - **Head Agent Coordinator**: Synthesizes passive recon, maps discovered attack surfaces, plans worker assignments, adjudicates findings, and compiles attack chains.
   - **9 Specialist Worker Agents**:
     - 🔍 `Recon Specialist`: DNS, WHOIS, technologies, attack surface mapping.
     - 🔑 `Secrets Hunter`: Deep credential carving, client-side secret triage.
     - 🛡️ `Headers Auditor`: CSP bypasses, framing risks, missing defenses.
     - 🌐 `CORS Analyst`: Null-origin trust, wildcard reflection with credentials.
     - ⚡ `XSS Specialist`: Benign canary injection and reflection context verification.
     - 🎯 `IDOR Hunter`: Parameterized route fuzzing and object authorization checks.
     - 🔐 `Auth & Session Auditor`: Token validation, session fixation, cookie scope.
     - 🕸️ `GraphQL Explorer`: Introspection analysis, field enumeration, batching attacks.
     - 🗺️ `Source Map Miner`: Automated discovery and parsing of unbundled source maps.

3. **Enterprise Security Ontology & OSDK**:
   - **Cryptographic Provenance Gate**: All agent-reported vulnerabilities are cryptographically anchored to immutable `evidence_blobs` via SHA-256 content addressing. Zero hallucinated findings allowed.
   - **Universal Archetype Classifier**: Automatically identifies `vibe_baas` (Firebase, Supabase, Appwrite), `modern_spa` (Next.js, Vite, React, Vue), `legacy_monolith` (CSRF-less HTML forms, session cookies), and `cms_platform` (WordPress, Drupal).
   - **BugSeek OSDK**: Deterministic graph queries traversing typed nodes (`Origin`, `Asset`, `Endpoint`, `Control`, `Sink`, `Resource`) and directional edges (`MUTATES`, `PROTECTS`, `CAN_INVOKE`, `FLOWS_TO`).
   - **4-Matrix Posture Model**: Evaluates $S = \text{clamp}(100 - R_{\text{ont}} + H_{\text{ctrl}} - \Delta_{\text{drift}}, 0, 100) \times C$, combining confidence-weighted risk, control hygiene, temporal regression drift, and coverage gating.

4. **Async 202 Accepted + Polling Architecture**:
   - Swarm jobs start in `<200ms` via HTTP `202 Accepted`, eliminating HTTP gateway timeouts on cloud platforms (e.g. Render free tier cold-starts).
   - The extension polls live progress (`/api/swarm/scans/:id`) and receives real-time agent status updates until completion.

---

## 🏗️ Architecture Overview

```
                               ┌────────────────────────────────────────────────────────┐
                               │                 Chrome Extension (MV3)                 │
                               │                                                        │
                               │  ┌───────────────────────┐  ┌───────────────────────┐  │
                               │  │   jsBundleScanner     │  │   DeepTaintEngine     │  │
                               │  │ (SPA API Routes/Params│  │ (Acorn AST Taint Sinks│  │
                               │  └──────────┬────────────┘  └───────────┬───────────┘  │
                               │             │                           │              │
                               │  ┌──────────▼───────────────────────────▼───────────┐  │
                               │  │                 SurfaceSnapshot                  │  │
                               │  │      (Observed APIs, Forms, Cookies, AST)        │  │
                               │  └──────────────────────┬───────────────────────────┘  │
                               └─────────────────────────┼──────────────────────────────┘
                                                         │ HTTP 202 (Enqueued) + Polling
                                                         ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│                                BugSeek Fastify / TypeScript Backend                           │
│                                                                                               │
│  ┌─────────────────────────────┐                  ┌────────────────────────────────────────┐  │
│  │    Universal Ingestion      │                  │         AIP Control Plane              │  │
│  │ (Archetypes & Evidence)     │                  │  (Tool Budgets & Execution Audit Logs) │  │
│  └──────────────┬──────────────┘                  └───────────────────┬────────────────────┘  │
│                 │                                                     │                       │
│  ┌──────────────▼─────────────────────────────────────────────────────▼────────────────────┐  │
│  │                       Security Ontology Graph (PostgreSQL)                              │  │
│  │           evidence_blobs  ◄───►  ontology_objects  ◄───►  ontology_links                │  │
│  └──────────────────────────────────────────────┬──────────────────────────────────────────┘  │
│                                                 │                                             │
│  ┌──────────────────────────────────────────────▼──────────────────────────────────────────┐  │
│  │                           BugSeekOSDK & Tool Dispatcher                                 │  │
│  │         getUnprotectedMutations  │  getBlastRadius  │  enforceProvenanceGate            │  │
│  └──────────────────────────────────────────────┬──────────────────────────────────────────┘  │
│                                                 │                                             │
│  ┌──────────────────────────────────────────────▼──────────────────────────────────────────┐  │
│  │                        Autonomous 9-Specialist AI Swarm                                 │  │
│  │     Head Agent ──► [Recon, Secrets, Headers, CORS, XSS, IDOR, Auth, GraphQL, Maps]      │  │
│  └────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Build & Load the Chrome Extension

```bash
# Clone the repository
git clone https://github.com/peeryamin17/busted.git
cd busted

# Install dependencies
npm install

# Build extension (Vite + CRXJS -> dist/)
npm run build
```

**Load unpacked in Chrome**:
1. Open `chrome://extensions/`
2. Toggle on **Developer mode** (top right)
3. Click **Load unpacked** (top left)
4. Select the `dist/` directory (or `/Users/peeryamin/Downloads/bugseek-extension/`)
5. Open any target tab and click the **BugSeek AI** icon in the toolbar.

---

### 2. Configure Your AI Key (BYOK)

BugSeek AI offers two convenient ways to use your own Gemini API key:
- **Direct in the Extension**: Open the extension popup, expand the settings row, paste your Gemini API key (`AIza...`), and click **Save**. This unlocks the AI Swarm instantly on your own Gemini quota with zero backend dependency.
- **On the Web Platform**: Log into [bugseek-ai.vercel.app](https://bugseek-ai.vercel.app), paste your key in Settings, and connect your extension with a single-click 32-character pairing code. The key is encrypted via **AES-256-GCM** in PostgreSQL and never exposed to the browser.

---

### 3. Run the Backend (Fastify + PostgreSQL)

The extension is fully functional standalone. To run the backend locally for zero-latency testing:

```bash
cd backend

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your GEMINI_API_KEY and DATABASE_URL

# Apply PostgreSQL ontology schema
node scripts/migrate.js

# Start backend in watch mode
npm run dev
```

Health check:
```bash
curl http://localhost:3000/health
# Response: {"status":"ok","version":"0.3.0","llm":"gemini"}
```

---

## 🧪 Running Test Suites

BugSeek maintains comprehensive end-to-end and unit test coverage across all subsystems:

```bash
# Backend unit & integration test suites:
cd backend
npx tsx test/ontology.test.ts  # Universal Ontology, OSDK, Ingestion & AIP Score
npx tsx test/swarm.test.ts     # Multi-Agent Swarm, 202 Accepted & Polling
npx tsx test/aiKey.test.ts     # AES-256-GCM Key Encryption & BYOK Gating
npx tsx test/pairing.test.ts   # One-Time 32-char Pairing Code Exchange
npx tsx test/v1compat.test.ts  # Backward Compatibility & Health Probes
npx tsx test/webcheck.test.ts  # Active Probes, SSRF Guardrails & Rate Limiting

# Extension typecheck & build:
cd ..
npm run typecheck
npm run build
```

---

## ⚖️ Legal & Ethical Guardrails

BugSeek AI strictly enforces legal and safety constraints at both the client and server levels:

- **Explicit Authorization Verification**: Active testing and swarm scans require explicit confirmation of target ownership, pentest engagement, or public bug bounty authorization before probes are dispatched.
- **SSRF & Scope Enforcement**: Every single HTTP request passes through strict target URL boundary matching and RFC 1918 / loopback IP address resolution guards.
- **Zero Raw Secrets Stored**: All sensitive evidence (passwords, JWTs, API tokens, PII) is redacted at collection and before database persistence using cryptographic masks.
- **Rate-Limiting Safeguards**: Configurable token-bucket rate limiters prevent denial-of-service against tested applications.

---

## 📜 License

UNLICENSED, Proprietary software. Built for authorized security researchers, bug bounty hunters, and internal AppSec teams.
