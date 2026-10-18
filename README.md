# 🛡️ SentinelGraph: Autonomous Codebase & Attack-Path Triage Agent

**Hackathon:** Graph Hacks: Context for AI Agents (Powered by FalkorDB)  
**Track Entered:** Track 01 — Agents That Act on Connected Data  
**Tech Stack:** FalkorDB (Graph Context Layer), Model Context Protocol (FastMCP), Google Gemini (`gemini-2.5-flash` / `gemini-2.5-pro`), Python, Streamlit  

---

## 🎯 The Problem & Why Connected Graphs Matter

Security scanners flood engineering teams with thousands of isolated alerts (such as CVEs on code packages or misconfigured services) without understanding how microservices, code dependencies, recent Git deployments, and sensitive databases actually connect. 

Standard Vector RAG fails at this task because chunk similarity cannot answer multi-hop relational questions like:
> *"Can an attacker on the public internet reach our PCI Credit Card Vault by chaining service-to-service calls through a newly deployed, vulnerable code package?"*

**SentinelGraph** solves this by placing the agent's operational context inside **FalkorDB**. Instead of guessing, the agent uses **Model Context Protocol (MCP)** tools to execute deterministic Cypher `shortestPath` traversals across the codebase and service mesh, calculates the upstream and downstream blast radius, mutates the graph to quarantine compromised services, and writes an explainable audit trail directly back into the graph.

---

## ✨ Key Track 01 Features Implemented

* **Multi-Hop Reasoning:** Traverses up to 6 hops across network routes (`:CALLS`), data access permissions (`:READS_WRITE`), code dependencies (`:DEPENDS_ON_CODE`), and vulnerabilities (`:HAS_VULNERABILITY`).
* **Graph Algorithms as Agent Tools:** Uses FalkorDB's `shortestPath` algorithm and multi-directional neighborhood traversals exposed via `@mcp.tool()`.
* **False-Positive Filtering:** Automatically distinguishes between non-exploitable surface bugs (`CVE-2026-1022` on `api-gateway`) and critical exploitable RCE chains (`CVE-2026-8841` on `order-svc`).
* **Actions Based on Graph State:** Mutates live graph properties to quarantine compromised services (`status: 'QUARANTINED'`) and creates connected `:AuditDecision` nodes.
* **100% Explainable Paths:** Outputs the exact node-by-node chain, vulnerable file path, CVE score, and introducing Git commit hash behind every decision.

---

## 🏗️ System Architecture

~~~text
User / Security Alert
        │
        ▼
┌──────────────────────────────────────────────────────────┐
│  Reasoning Engine: Google Gemini (2.5 Flash / 2.5 Pro)   │
└───────────────────────────┬──────────────────────────────┘
                            │ Invokes MCP Tools
                            ▼
┌──────────────────────────────────────────────────────────┐
│  FastMCP Tool Layer (graph_tools.py)                     │
│  ├── scan_exploitable_attack_paths(target_database_id)   │
│  ├── calculate_service_blast_radius(service_id)          │
│  └── execute_security_remediation(service_id, action)    │
└───────────────────────────┬──────────────────────────────┘
                            │ OpenCypher / GraphBLAS
                            ▼
┌──────────────────────────────────────────────────────────┐
│  FalkorDB Context & Memory Layer (Port 6379 / 3000)      │
│  (:Service)-[:CALLS]->(:Service)-[:READS_WRITE]->(:DB)   │
│  (:Service)-[:DEPENDS_ON_CODE]->(:Package)-[:HAS_VULN]   │
│  (:Deployment)-[:DEPLOYED_TO]->(:Service)                │
│  (:AuditDecision)-[:APPLIED_TO]->(:Service)              │
└──────────────────────────────────────────────────────────┘
~~~

---

## 🕸️ FalkorDB Graph Data Model (Schema)

### Node Labels
| Node Label | Key Properties | Role in Agent Reasoning |
| :--- | :--- | :--- |
| `:Service` | `id`, `name`, `exposed_to_internet`, `tier`, `status`, `owner` | Represents a microservice in the production mesh. |
| `:Database` | `id`, `name`, `classification`, `encrypted` | Represents sensitive data stores (`crown-jewel`, `confidential`). |
| `:Package` | `id`, `language`, `file_path` | Tracks code dependencies and exact source file locations. |
| `:Vulnerability` | `id`, `severity`, `cvss`, `type`, `exploitable` | Stores CVE metadata attached to specific code packages. |
| `:Deployment` | `id`, `commit`, `author`, `timestamp`, `change_summary` | Links recent Git commits to microservices for root-cause attribution. |
| `:AuditDecision` | `action`, `justification`, `executed_by` | Written into FalkorDB by the agent to record explainable actions. |

### Relationships (Edges)
* `(:Service)-[:CALLS {protocol, port}]->(:Service)` — Service-to-service network calls.
* `(:Service)-[:READS_WRITE {iam_role}]->(:Database)` — Database read/write access permissions.
* `(:Service)-[:DEPENDS_ON_CODE]->(:Package)` — Maps microservices to underlying code libraries.
* `(:Package)-[:HAS_VULNERABILITY]->(:Vulnerability)` — Flags known CVEs on code packages.
* `(:Deployment)-[:DEPLOYED_TO]->(:Service)` — Tracks which commit modified which service.
* `(:AuditDecision)-[:APPLIED_TO]->(:Service)` — Connects the agent's remediation decision to the target node.

---

## 🔍 Core Cypher Queries Executed by the Agent

### 1. Multi-Hop Attack Path Discovery (`shortestPath`)
Locates whether an internet-exposed entry point can reach a crown-jewel database through an exploitable vulnerability, while correlating the exact code file path and Git commit:

~~~cypher
MATCH (entry:Service {exposed_to_internet: true})
MATCH (target:Database {id: $db_id})
MATCH path = shortestPath((entry)-[:CALLS|READS_WRITE*1..6]->(target))
UNWIND nodes(path) AS node
OPTIONAL MATCH (node)-[:DEPENDS_ON_CODE]->(pkg:Package)-[:HAS_VULNERABILITY]->(cve:Vulnerability {exploitable: true})
OPTIONAL MATCH (dep:Deployment)-[:DEPLOYED_TO]->(node)
RETURN 
    [n IN nodes(path) | n.id] AS full_attack_chain,
    node.id AS vulnerable_service,
    pkg.id AS vulnerable_package,
    pkg.file_path AS code_file_path,
    cve.id AS cve_id,
    cve.cvss AS cvss_score,
    dep.commit AS introducing_commit
~~~

### 2. Upstream & Downstream Blast-Radius Calculation
Traverses up to 4 hops upstream (callers that will be impacted if the service is quarantined) and 4 hops downstream (databases and services exposed):

~~~cypher
MATCH (s:Service {id: $svc_id})
OPTIONAL MATCH up_path = (caller:Service)-[:CALLS*1..4]->(s)
OPTIONAL MATCH down_path = (s)-[:CALLS|READS_WRITE*1..4]->(downstream)
RETURN 
    s.owner AS owner_team,
    collect(DISTINCT caller.id) AS upstream_callers_affected,
    collect(DISTINCT downstream.id) AS downstream_assets_at_risk
~~~

### 3. Autonomous Graph Remediation & Audit Trail
Mutates the compromised microservice's status and attaches an immutable `:AuditDecision` node explaining why the action was taken:

~~~cypher
MATCH (s:Service {id: $svc_id})
SET s.status = $action
CREATE (a:AuditDecision {
    action: $action,
    justification: $reason,
    executed_by: 'SentinelGraph-Agent'
})
CREATE (a)-[:APPLIED_TO]->(s)
RETURN s.id, s.status, a.action
~~~

---

## 🚀 Step-by-Step Local Setup Instructions

### Prerequisites
1. **Docker Desktop** installed and running.
2. **Python 3.10+** installed.
3. **Free Google Gemini API Key** (Get one for free without a credit card at [aistudio.google.com/apikey](https://aistudio.google.com/apikey)).

### 1. Start FalkorDB (Database + Visual Browser)
Run the official FalkorDB container exposing port `6379` (database) and port `3000` (visual web UI):

~~~bash
docker run -d -p 6379:6379 -p 3000:3000 --name falkordb-hack falkordb/falkordb:latest
~~~

### 2. Clone the Repository & Install Dependencies
~~~bash
git clone https://github.com/YOUR-USERNAME/sentinel-graph-falkordb.git
cd sentinel-graph-falkordb
pip install -U "google-genai>=2.30.1" falkordb mcp streamlit
~~~

### 3. Launch the SentinelGraph Dashboard
~~~bash
streamlit run app.py
~~~

* **Agent Command UI:** Open `http://localhost:8501` in your browser, paste your free Gemini API Key into the sidebar, and click **Run Autonomous Graph Investigation**.
* **FalkorDB Visual Graph Browser:** Open `http://localhost:3000` in your browser to inspect the live nodes, edges, and `:AuditDecision` updates visually.

---

## 📂 Repository Structure

~~~text
├── app.py              # Streamlit UI & Gemini multi-step tool-calling orchestrator
├── graph_tools.py      # FalkorDB connection, graph seeding, and FastMCP tools
└── README.md           # Architecture, schema, Cypher queries, and setup guide
~~~

---

## 🤖 Disclosure of AI Assistance
In accordance with the Graph Hacks rules, AI assistance (Google Gemini) was used to help structure the Streamlit dashboard interface, MCP tool wrappers, and documentation formatting. All FalkorDB schemas, multi-hop Cypher queries, and graph state mutations are executed deterministically against a live FalkorDB instance.