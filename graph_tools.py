import json
from falkordb import FalkorDB
from mcp.server.fastmcp import FastMCP

# Initialize MCP Server for Track 1 compliance
mcp = FastMCP("SentinelGraph-Cyber-Microservices")

# Connect to local FalkorDB instance
db = FalkorDB(host="localhost", port=6379)
graph = db.select_graph("CyberMicroserviceGraph")

# Keep an execution log so the UI can show the exact graph path behind every answer
TOOL_EXECUTION_LOG = []


def seed_cyber_graph():
  """Populates FalkorDB with a realistic microservice codebase, CVEs, and databases."""
  graph.query("MATCH (n) DETACH DELETE n")  # Clean slate

  cypher_seed = """
    // 1. Create Microservices
    CREATE (gw:Service {id: 'api-gateway', name: 'Public API Gateway', exposed_to_internet: true, tier: 'tier-1', status: 'healthy', owner: 'Platform Team'})
    CREATE (auth:Service {id: 'auth-svc', name: 'OAuth Identity Service', exposed_to_internet: false, tier: 'tier-1', status: 'healthy', owner: 'Security Team'})
    CREATE (order:Service {id: 'order-svc', name: 'Order Checkout Service', exposed_to_internet: false, tier: 'tier-1', status: 'degraded', owner: 'Commerce Team'})
    CREATE (pay:Service {id: 'payment-svc', name: 'Payment Processor', exposed_to_internet: false, tier: 'critical', status: 'healthy', owner: 'FinTech Team'})
    CREATE ( analytics:Service {id: 'analytics-svc', name: 'Telemetry Worker', exposed_to_internet: false, tier: 'tier-3', status: 'healthy', owner: 'Data Team'})

    // 2. Create Crown-Jewel Databases
    CREATE (vault:Database {id: 'pci-card-vault', name: 'PCI-DSS Credit Card Vault', classification: 'crown-jewel', encrypted: true})
    CREATE (userdb:Database {id: 'users-pg', name: 'Customer Identity DB', classification: 'confidential', encrypted: true})

    // 3. Create Code Packages & Security Vulnerabilities (CVEs)
    CREATE (pkg1:Package {id: 'xml-fast-parser@2.1.0', language: 'Python', file_path: 'src/checkout/xml_parser.py'})
    CREATE (pkg2:Package {id: 'ui-logger@1.0.4', language: 'NodeJS', file_path: 'src/gateway/logger.js'})
    CREATE (cve1:Vulnerability {id: 'CVE-2026-8841', severity: 'CRITICAL', cvss: 9.8, type: 'Remote Code Execution (RCE)', exploitable: true})
    CREATE (cve2:Vulnerability {id: 'CVE-2026-1022', severity: 'LOW', cvss: 3.1, type: 'Header Info Leak', exploitable: false})

    // 4. Create Recent Code Deployments
    CREATE (dep1:Deployment {id: 'deploy-994', commit: '8f3a19c', author: 'dev_rahul', timestamp: '14 mins ago', change_summary: 'Added XML invoice upload parser'})

    // 5. Connect the Graph (Multi-Hop Relationships)
    CREATE (gw)-[:CALLS {protocol: 'HTTPS', port: 443}]->(auth)
    CREATE (gw)-[:CALLS {protocol: 'gRPC', port: 50051}]->(order)
    CREATE (order)-[:CALLS {protocol: 'gRPC', port: 50052}]->(pay)
    CREATE (order)-[:CALLS {protocol: 'AMQP', port: 5672}]->(analytics)
    CREATE (auth)-[:READS_WRITE]->(userdb)
    CREATE (pay)-[:READS_WRITE {iam_role: 'PaymentAdminRole'}]->(vault)

    CREATE (order)-[:DEPENDS_ON_CODE]->(pkg1)
    CREATE (gw)-[:DEPENDS_ON_CODE]->(pkg2)
    CREATE (pkg1)-[:HAS_VULNERABILITY]->(cve1)
    CREATE (pkg2)-[:HAS_VULNERABILITY]->(cve2)
    CREATE (dep1)-[:DEPLOYED_TO]->(order)
    """
  graph.query(cypher_seed)
  return "Graph seeded with 5 Microservices, 2 Databases, 2 CVEs, and 1 Deployment."


@mcp.tool()
def scan_exploitable_attack_paths(target_database_id: str) -> str:
  """Runs a multi-hop shortest-path traversal in FalkorDB to find if any internet-exposed

  microservice can reach a crown-jewel database through services with CRITICAL
  vulnerabilities.
  """
  query = """
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
    """
  res = graph.query(query, {"db_id": target_database_id})
  findings = []
  for row in res.result_set:
    if row[4] is not None:  # Only record hops with an exploitable CVE
      findings.append({
          "attack_chain_path": " -> ".join(row[0]),
          "vulnerable_microservice": row[1],
          "vulnerable_code_package": row[2],
          "file_location": row[3],
          "cve_id": row[4],
          "cvss_score": row[5],
          "introduced_by_commit": row[6],
      })
  output = json.dumps(findings, indent=2)
  TOOL_EXECUTION_LOG.append(
      {"tool": "scan_exploitable_attack_paths", "result": findings}
  )
  return output


@mcp.tool()
def calculate_service_blast_radius(service_id: str) -> str:
  """Traverses upstream callers and downstream dependencies (up to 4 hops) in FalkorDB

  to measure what breaks or gets exposed if the given microservice is
  compromised or isolated.
  """
  query = """
    MATCH (s:Service {id: $svc_id})
    OPTIONAL MATCH up_path = (caller:Service)-[:CALLS*1..4]->(s)
    OPTIONAL MATCH down_path = (s)-[:CALLS|READS_WRITE*1..4]->(downstream)
    RETURN 
        s.owner AS owner_team,
        collect(DISTINCT caller.id) AS upstream_callers_affected,
        collect(DISTINCT downstream.id) AS downstream_assets_at_risk
    """
  res = graph.query(query, {"svc_id": service_id})
  row = res.result_set[0] if res.result_set else ["Unknown", [], []]
  data = {
      "target_service": service_id,
      "owner_team": row[0],
      "upstream_services_impacted_if_quarantined": row[1],
      "downstream_services_and_dbs_exposed": row[2],
  }
  TOOL_EXECUTION_LOG.append(
      {"tool": "calculate_service_blast_radius", "result": data}
  )
  return json.dumps(data, indent=2)


@mcp.tool()
def execute_security_remediation(
    service_id: str, action: str, justification: str
) -> str:
  """Mutates the FalkorDB graph state to isolate/quarantine a vulnerable service

  and writes an immutable AuditNode connected to the service for explainability.
  """
  query = """
    MATCH (s:Service {id: $svc_id})
    SET s.status = $action
    CREATE (a:AuditDecision {
        action: $action,
        justification: $reason,
        executed_by: 'Gemini-4-Argon-High-Agent'
    })
    CREATE (a)-[:APPLIED_TO]->(s)
    RETURN s.id, s.status, a.action
    """
  graph.query(
      query, {"svc_id": service_id, "action": action, "reason": justification}
  )
  result_msg = {
      "service_updated": service_id,
      "new_graph_status": action,
      "audit_trail_recorded": True,
      "justification": justification,
  }
  TOOL_EXECUTION_LOG.append(
      {"tool": "execute_security_remediation", "result": result_msg}
  )
  return json.dumps(result_msg, indent=2)