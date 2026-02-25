# piqrypt-langchain

**Verifiable AI Agent Memory for LangChain.**

[![PyPI](https://img.shields.io/pypi/v/piqrypt-langchain)](https://pypi.org/project/piqrypt-langchain/)
[![Downloads](https://img.shields.io/pypi/dm/piqrypt-langchain)](https://pypi.org/project/piqrypt-langchain/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PiQrypt](https://img.shields.io/badge/powered%20by-PiQrypt-blue)](https://github.com/piqrypt/piqrypt)

Every tool call, LLM response, chain execution, and agent action — signed, hash-chained, tamper-proof.

```bash
pip install piqrypt-langchain
```

---

## Quickstart — attach once, stamp everything

```python
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_tools_agent
from piqrypt_langchain import PiQryptCallbackHandler

# One handler — stamps every LLM call, tool call, and chain event
handler = PiQryptCallbackHandler(identity_file="my-agent.json")

llm = ChatOpenAI(model="gpt-4o", callbacks=[handler])
agent = create_openai_tools_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])

result = executor.invoke({"input": "Analyze Q4 sales and flag anomalies"})

# Export verifiable memory
handler.export_audit("q4-analysis-audit.json")
# $ piqrypt verify q4-analysis-audit.json
```

---

## Drop-in AgentExecutor

```python
from piqrypt_langchain import AuditedAgentExecutor

# Replace AgentExecutor with AuditedAgentExecutor
executor = AuditedAgentExecutor(
    agent=your_agent,
    tools=your_tools,
    identity_file="my-agent.json"
)

result = executor.invoke({"input": "Your query here"})
executor.export_audit("audit.json")
```

---

## Wrap individual tools

```python
from langchain.tools import tool
from piqrypt_langchain import piqrypt_tool

@tool
@piqrypt_tool(identity_file="my-agent.json")
def search_web(query: str) -> str:
    """Search the web for information."""
    return your_search_logic(query)

@tool
@piqrypt_tool(identity_file="my-agent.json")
def execute_sql(query: str) -> str:
    """Execute a SQL query."""
    return your_db_logic(query)
```

---

## Wrap chain functions

```python
from piqrypt_langchain import stamp_chain

@stamp_chain("document_analysis", identity_file="my-agent.json")
def analyze_document(doc: str) -> dict:
    return your_chain.invoke({"input": doc})
```

---

## What gets stamped

| Event | When |
|---|---|
| `callback_handler_initialized` | Handler creation |
| `llm_response` | After every LLM call |
| `tool_start` | Before tool execution |
| `tool_end` | After tool execution |
| `tool_error` | On tool failure |
| `chain_start` | Before chain runs |
| `chain_end` | After chain completes |
| `agent_action` | Every agent decision |
| `agent_finish` | Agent completion |
| `executor_invoke` | AgentExecutor input |
| `executor_complete` | AgentExecutor output |

All events Ed25519-signed, SHA-256 hash-chained.  
Raw inputs and outputs **never stored** — only their SHA-256 hashes.

---

## Verify

```bash
piqrypt verify langchain-audit.json
# ✅ Chain integrity verified — 32 events, 0 forks

piqrypt search --type tool_error
# All tool failures with timestamps
```

---

## Why the callback handler is the best approach

LangChain's callback system is designed exactly for this — attach once at the top level, every nested component fires the same callbacks. One `PiQryptCallbackHandler` stamps your entire agent pipeline automatically, including:

- Every LLM call inside chains
- Every tool invocation
- Every intermediate chain step
- Every agent decision

No need to modify individual tools or chains.

---

## Scope

| Use case | AISS profile |
|---|---|
| Development / PoC | AISS-1 (Free, included) |
| Non-critical production | AISS-1 (Free) |
| Regulated production | AISS-2 (Pro) |

---

## Links

- **PiQrypt core:** [github.com/piqrypt/piqrypt](https://github.com/piqrypt/piqrypt)
- **Integration guide:** [INTEGRATION.md — LangChain](https://github.com/piqrypt/piqrypt/blob/main/INTEGRATION.md#3-langchain)
- **Issues:** piqrypt@gmail.com

---

*PiQrypt — Verifiable AI Agent Memory*  

