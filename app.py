import time
from google import genai
from google.genai import errors, types
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
)

# Sidebar Configuration
with st.sidebar:
  st.header("🔑 Free AI Configuration")
  api_key = st.text_input(
      "Enter Free Gemini API Key",
      type="password",
      help="Get a free key at https://aistudio.google.com/apikey",
  )
  model_choice = st.selectbox(
      "Select Model",
      ["gemini-3.5-flash-lite", "gemini-3.8-flash", "gemini-3.6-flash"],
      index=0,
      help=(
          "gemini-3.5-flash-lite has the highest Free Tier rate limit so it"
          " won't hit 429 errors."
      ),
  )
  thinking_level = st.selectbox(
      "Thinking Level",
      ["medium", "high", "low"],
      index=0,
      help="Controls reasoning depth before calling FalkorDB tools.",
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
  table_placeholder = st.empty()

  def render_graph_table():
    res = graph.query(
        "MATCH (s:Service) RETURN s.id, s.tier, s.status, s.owner"
    )
    services_table = [
        {"Microservice": r[0], "Tier": r[1], "Graph Status": r[2], "Owner": r[3]}
        for r in res.result_set
    ]
    table_placeholder.table(services_table)

  render_graph_table()

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
      "🚀 Run Autonomous Graph Investigation",
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
          " Agent. You NEVER guess. Call your FalkorDB graph tools to traverse"
          " multi-hop connections. Where possible, batch tool calls together to"
          " minimize round-trips. Always cite the exact node-to-node path"
          " (e.g., api-gateway -> order-svc -> payment-svc -> pci-card-vault)"
          " and mutate the graph using execute_security_remediation when a"
          " critical RCE path to a crown-jewel database is verified."
      )

      # Automatic fallback list in case one model hits the 5 RPM free limit
      fallback_models = [model_choice] + [
          m
          for m in [
              "gemini-3.5-flash-lite",
              "gemini-3.8-flash",
              "gemini-3.6-flash",
          ]
          if m != model_choice
      ]

      response = None
      for active_model in fallback_models:
        try:
          with st.spinner(
              f"Running {active_model} over FalkorDB connected data..."
          ):
            response = client.models.generate_content(
                model=active_model,
                contents=user_query,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    thinking_config=types.ThinkingConfig(
                        thinking_level=thinking_level
                    ),
                    tools=[
                        scan_exploitable_attack_paths,
                        calculate_service_blast_radius,
                        execute_security_remediation,
                    ],
                ),
            )
          break  # Success! Exit loop
        except errors.ClientError as e:
          if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
            st.warning(
                f"⏳ Free tier rate limit reached on `{active_model}`."
                " Switching to backup model bucket..."
            )
            time.sleep(2)
          else:
            st.error(f"API Error: {e}")
            break

      if response is None:
        st.warning(
            "All free model buckets are cooling down. Waiting 30 seconds before"
            " final retry..."
        )
        time.sleep(30)
        response = client.models.generate_content(
            model="gemini-3.5-flash-lite",
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

      if response:
        # Refresh the left-hand table immediately so 'QUARANTINED' shows up
        render_graph_table()

        st.markdown("### 🛠️ Multi-Hop FalkorDB Tools Executed")
        for idx, entry in enumerate(TOOL_EXECUTION_LOG, 1):
          with st.expander(f"Step {idx}: `{entry['tool']}`", expanded=True):
            st.json(entry["result"])

        st.markdown("### 📋 Final Explainable Security Verdict")
        st.markdown(response.text)