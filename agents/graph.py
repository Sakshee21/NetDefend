"""LangGraph wiring for the NetDefend pipeline.

Nodes and edges only — all agent logic and prompt construction lives in the
individual agent modules.

    packet_agent
        -> intrusion_agent
            -> threat_agent          (parallel branch)
            -> troubleshooting_agent (parallel branch)
                -> arbiter           (waits for both branches)
                    -> response_agent
                        -> END

Two notes on the langgraph 0.2.0 API, which is what this project pins:

* Fan-out cannot be two plain add_edge calls from the same node. That
  version only allows multiple outgoing edges when the state schema has an
  Annotated reducer key, and NetDefendState deliberately has none — it is a
  fixed contract shared with the backend and frontend. A conditional edge
  whose path function always returns both targets fans out to both nodes in
  the same superstep, which is the parallelism we want.
* Fan-in uses the list form of add_edge. That registers a waiting edge, so
  the arbiter runs once, only after both branches have finished.

The two branches write disjoint state keys, so no reducer is needed to
merge their updates.
"""

from langgraph.graph import END, StateGraph

from agents.arbiter import run_arbiter
from agents.intrusion_agent import run_intrusion_agent
from agents.packet_agent import run_packet_agent
from agents.response_agent import run_response_agent
from agents.state_schema import NetDefendState
from agents.threat_agent import run_threat_agent
from agents.troubleshooting_agent import run_troubleshooting_agent

HYPOTHESIS_BRANCHES = ["threat_agent", "troubleshooting_agent"]


def _fan_out_to_both_hypotheses(state: NetDefendState) -> list:
    """Always schedule both hypothesis agents.

    This is an unconditional fan-out expressed as a conditional edge; see
    the module docstring for why.
    """
    return HYPOTHESIS_BRANCHES


def build_graph():
    """Build and compile the NetDefend agent graph.

    Returns:
        The compiled LangGraph application.
    """
    builder = StateGraph(NetDefendState)

    builder.add_node("packet_agent", run_packet_agent)
    builder.add_node("intrusion_agent", run_intrusion_agent)
    builder.add_node("threat_agent", run_threat_agent)
    builder.add_node("troubleshooting_agent", run_troubleshooting_agent)
    builder.add_node("arbiter", run_arbiter)
    builder.add_node("response_agent", run_response_agent)

    builder.set_entry_point("packet_agent")

    builder.add_edge("packet_agent", "intrusion_agent")

    # Fan out: both hypothesis agents run from the same ML prediction.
    builder.add_conditional_edges(
        "intrusion_agent",
        _fan_out_to_both_hypotheses,
        HYPOTHESIS_BRANCHES,
    )

    # Fan in: the arbiter runs once, after both branches complete.
    builder.add_edge(HYPOTHESIS_BRANCHES, "arbiter")

    builder.add_edge("arbiter", "response_agent")
    builder.add_edge("response_agent", END)

    return builder.compile()


app = build_graph()
