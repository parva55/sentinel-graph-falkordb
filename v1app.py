# import json
# from google import genai
# from google.genai import types
# from graph_tools import (
#     TOOL_EXECUTION_LOG,
#     calculate_service_blast_radius,
#     execute_security_remediation,
#     graph,
#     scan_exploitable_attack_paths,
#     seed_cyber_graph,
# )
# import streamlit as st

# st.set_page_config(page_title="SentinelGraph | FalkorDB + Argon High", layout="wide")

# st.title("🛡️ SentinelGraph: Autonomous Codebase & Attack-Path Agent")
# st.caption("Track 1: Agents That Act on Connected Data | Powered by FalkorDB & Gemini 4 Argon (thinking_level='high')")

# # Sidebar Configuration
# with st.sidebar:
#     st.header("🔑 Configuration")
#     api_key = st.text_input("Enter Gemini API Key", type="password")
#     model_choice = st.selectbox(
#         "Select Model",
#         ["gemini-4-argon", "gemini-3.7-flash"],
#         index=0,
#         help="Use gemini-4-argon with thinking_level='high' for deep security reasoning."
#     )
#     thinking_level = st.selectbox("Argon Thinking Level", ["high", "medium", "low"], index=0)

#     if st.button("🔄 Reset & Seed FalkorDB Graph", use_container_width=True):
#         msg = seed_cyber_graph()
#         st.success(msg)

# # Ensure graph has data on first load
# if "initialized" not in st.session_state:
#     seed_cyber_graph()
#     st.session_state.initialized = True

# col1, col2 = st.columns([1, 1])

# with col1:
#     st.subheader("🕸️ Live FalkorDB Graph State")
#     res = graph.query("MATCH (s:Service) RETURN s.id, s.tier, s.status, s.owner")
#     services_table = [
#         {"Microservice": r[0], "Tier": r[1], "Graph Status": r[2], "Owner": r[3]}
#         for r in res.result_set
#     ]
#     st.table(services_table)

#     st.info("💡 **Tip:** You can also view the visual 3D node-and-edge graph live in your browser at **http://localhost:3000**")

#     default_prompt = (
#         "Investigate if there is an active, exploitable attack path reaching our 'pci-card-vault' database. "
#         "If you find a vulnerable microservice in the path, calculate its blast radius, automatically "
#         "quarantine that service in the graph, and provide a full explainable report showing the exact "
#         "nodes, edges, CVE, file path, and commit hash."
#     )
#     user_query = st.text_area("🎯 Mission Prompt for the Agent:", value=default_prompt, height=130)
#     run_btn = st.button("🚀 Run Autonomous Graph Investigation (Argon High)", type="primary", use_container_width=True)

# with col2:
#     st.subheader("🧠 Agent Reasoning & Graph Path Trace")
#     if run_btn:
#         if not api_key:
#             st.error("Please enter your Gemini API Key in the left sidebar first!")
#         else:
#             TOOL_EXECUTION_LOG.clear()
#             client = genai.Client(api_key=api_key)

#             system_instruction = (
#                 "You are a Principal Cybersecurity Architect and Autonomous DevSecOps Agent. "
#                 "You NEVER guess. You must always call your FalkorDB graph tools to traverse multi-hop "
#                 "connections before making a decision. Always cite the exact node-to-node path "
#                 "(e.g., api-gateway -> order-svc -> payment-svc -> pci-card-vault) and mutate the graph "
#                 "using execute_security_remediation when a critical RCE path to a crown-jewel database is verified."
#             )

#             with st.spinner(f"Running {model_choice} (thinking_level='{thinking_level}') over FalkorDB..."):
#                 config_args = {
#                     "system_instruction": system_instruction,
#                     "max_output_tokens": 65536,
#                     "tools": [
#                         scan_exploitable_attack_paths,
#                         calculate_service_blast_radius,
#                         execute_security_remediation,
#                     ],
#                 }
#                 # Configure thinking_level="high" for Gemini 4 Argon
#                 if model_choice == "gemini-4-argon":
#                     config_args["thinking_config"] = types.ThinkingConfig(
#                         thinking_level=thinking_level
#                     )

#                 response = client.models.generate_content(
#                     model=model_choice,
#                     contents=user_query,
#                     config=types.GenerateContentConfig(**config_args),
#                 )

#             st.markdown("### 🛠️ Multi-Hop FalkorDB Tools Executed")
#             for idx, entry in enumerate(TOOL_EXECUTION_LOG, 1):
#                 with st.expander(f"Step {idx}: `{entry['tool']}`", expanded=True):
#                     st.json(entry["result"])

#             st.markdown("### 📋 Final Explainable Security Verdict")
#             st.markdown(response.text)
#             st.rerun()


from google import genai
from google.genai import types
from graph_tools import (
    TOOL_EXECUTION_LOG,
    calculate_service_blast_radius,
    execute_security_remediation,
    graph,
    scan_exploitable_attack_paths,
    seed_cyber_graph,
)
import streamlit as st

st.set_page_config(
    page_title="SentinelGraph | FalkorDB Security Agent", layout="wide"
)

st.title("🛡️ SentinelGraph: Autonomous Codebase & Attack-Path Agent")
st.caption(
    "Track 01: Agents That Act on Connected Data | Powered by FalkorDB & Gemini"
    " Free Tier"
)

# Sidebar Configuration
with st.sidebar:
  st.header("🔑 Free AI Configuration")
  api_key = st.text_input(
      "Enter Free Gemini API Key",
      type="password",
      help=(
          "Get a 100% free key (no credit card needed) at"
          " https://aistudio.google.com/"
      ),
  )
  model_choice = st.selectbox(
      "Select Free Model",
      [
          "gemini-3.8-flash",
          "gemini-3.5-flash-lite",
          "gemini-3.6-flash",
          "gemini-4-argon",
      ],
      index=0,
      help=(
          "gemini-3.8-flash and gemini-3.5-flash-lite are free on Google AI"
          "Google AI Studio."
      ),
  )

  if st.button("🔄 Reset & Seed FalkorDB Graph", use_container_width=True):
    msg = seed_cyber_graph()
    st.success(msg)

# Ensure graph has data on first load
if "initialized" not in st.session_state:
  seed_cyber_graph()
  st.session_state.initialized = True

col1, col2 = st.columns([1, 1])

with col1:
  st.subheader("🕸️ Live FalkorDB Graph State")
  res = graph.query("MATCH (s:Service) RETURN s.id, s.tier, s.status, s.owner")
  services_table = [
      {"Microservice": r[0], "Tier": r[1], "Graph Status": r[2], "Owner": r[3]}
      for r in res.result_set
  ]
  st.table(services_table)

  st.info(
      "💡 **Tip:** View the interactive node-and-edge graph live in your"
      " browser at **http://localhost:3000**"
  )

  default_prompt = (
      "Investigate if there is an active, exploitable attack path reaching our"
      " 'pci-card-vault' database. If you find a vulnerable microservice in the"
      " path, calculate its blast radius, automatically quarantine that service"
      " in the graph, and provide a full explainable report showing the exact"
      " nodes, edges, CVE, file path, and commit hash."
  )
  user_query = st.text_area(
      "🎯 Mission Prompt for the Agent:", value=default_prompt, height=130
  )
  run_btn = st.button(
      "🚀 Run Autonomous Graph Investigation (Free Model)",
      type="primary",
      use_container_width=True,
  )

with col2:
  st.subheader("🧠 Agent Reasoning & Graph Path Trace")
  if run_btn:
    if not api_key:
      st.error(
          "Please paste your free Gemini API Key in the left sidebar first!"
      )
    else:
      TOOL_EXECUTION_LOG.clear()
      client = genai.Client(api_key=api_key)

      system_instruction = (
          "You are a Principal Cybersecurity Architect and Autonomous DevSecOps"
          " Agent. You NEVER guess. You must always call your FalkorDB graph"
          " tools to traverse multi-hop connections before making a decision."
          " Always cite the exact node-to-node path (e.g., api-gateway ->"
          " order-svc -> payment-svc -> pci-card-vault) and mutate the graph"
          " using execute_security_remediation when a critical RCE path to a"
          " crown-jewel database is verified."
      )

      with st.spinner(
          f"Running {model_choice} over FalkorDB connected data..."
      ):
        response = client.models.generate_content(
            model=model_choice,
            contents=user_query,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                tools=[
                    scan_exploitable_attack_paths,
                    calculate_service_blast_radius,
                    execute_security_remediation,
                ],
            ),
        )

      st.markdown("### 🛠️ Multi-Hop FalkorDB Tools Executed")
      for idx, entry in enumerate(TOOL_EXECUTION_LOG, 1):
        with st.expander(f"Step {idx}: `{entry['tool']}`", expanded=True):
          st.json(entry["result"])

      st.markdown("### 📋 Final Explainable Security Verdict")
      st.markdown(response.text)