import asyncio
import os
import requests
import json
from datetime import datetime
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, START, END
from typing import TypedDict, List, Dict
from typing_extensions import Annotated
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from dotenv import load_dotenv

load_dotenv()

# Slack functions remain unchanged
async def send_to_slack(message: str, webhook_url: str = None) -> bool:
    # ... (same as before) ...
    if not webhook_url:
        webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("⚠️ No Slack webhook URL found. Set SLACK_WEBHOOK_URL in .env file")
        return False
    try:
        slack_payload = { "text": "🔒 Security Analysis Report", "blocks": [ { "type": "header", "text": { "type": "plain_text", "text": "🔒 Security Analysis Report" } }, { "type": "section", "fields": [ { "type": "mrkdwn", "text": f"*Timestamp:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}" }, { "type": "mrkdwn", "text": f"*Analysis Type:* Automated Security Scan" } ] }, { "type": "section", "text": { "type": "mrkdwn", "text": f"```\n{message}\n```" } } ] }
        response = requests.post(webhook_url, json=slack_payload, headers={'Content-Type': 'application/json'}, timeout=10)
        if response.status_code == 200:
            print("✅ Security report sent to Slack successfully!")
            return True
        else:
            print(f"❌ Failed to send to Slack. Status: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error sending to Slack: {str(e)}")
        return False

def format_security_report_for_slack(report_content: str) -> str:
    # ... (same as before) ...
    if len(report_content) > 2800:
        report_content = report_content[:2800] + "\n...\n[Report truncated - see full details in logs]"
    return report_content


# MODIFIED: Updated the state to handle code content directly
class SecurityAnalysisState(TypedDict):
    messages: Annotated[List, add_messages]
    code_queue: List[Dict[str, str]] # A queue of {"filename": "...", "content": "..."}
    processed_files: List[str]
    scan_results: List[dict]
    current_phase: str

async def main():
    model = ChatOpenAI(model="gpt-4o", temperature=0)

    # MODIFIED: Removed the "filesystem" server as it's no longer needed.
    client = MultiServerMCPClient(
        {
            "semgrep": {
                "url": "https://mcp.semgrep.ai/mcp",
                "transport": "streamable_http",
            },
        }
    )
    
    try:
        tools = await client.get_tools()
        print("✅ MCP tools loaded successfully.")
    except Exception as e:
        print(f"⚠️ Warning: MCP tools failed to load ({str(e)}) – continuing without tools.")
        tools = []

    model_with_tools = model.bind_tools(tools) if tools else model
    tool_node = ToolNode(tools) if tools else None

    # --- Agent Definitions ---

    # MODIFIED: This agent now populates a code_queue instead of creating files.
    async def discovery_agent(state: SecurityAnalysisState):
        """Fetches code from the API endpoint and prepares it for scanning."""
        print("--- DISCOVERY PHASE (via API) ---")
        api_endpoint = "http://localhost:8000/api/v1/commits/latest"
        code_to_scan = []

        try:
            print(f"Fetching code from {api_endpoint}...")
            response = requests.get(api_endpoint, timeout=15)
            response.raise_for_status()
            api_data = response.json()

            # Handle the actual API response format
            if not isinstance(api_data, dict) or "data" not in api_data:
                print(f"⚠️ Error: API response must be a JSON object with 'data' field. Got {type(api_data).__name__}.")
                return {
                    "code_queue": [],
                    "processed_files": [],
                    "scan_results": [],
                    "current_phase": "processing"
                }

            commit_data = api_data["data"]
            
            # Extract file diffs from the commit data
            file_diffs = commit_data.get("file_diffs", [])
            
            if not file_diffs:
                print("⚠️ No file diffs found in the commit data.")
                return {
                    "code_queue": [],
                    "processed_files": [],
                    "scan_results": [],
                    "current_phase": "processing"
                }

            for file_diff in file_diffs:
                filename = file_diff.get("file_name", f"unknown_file_{len(code_to_scan)}.tmp")
                diff_content = file_diff.get("diff", "")
                
                # Skip binary files or files without meaningful content
                if "Binary files" in diff_content or not diff_content.strip():
                    print(f"⚠️ Skipping binary or empty file: {filename}")
                    continue
                
                # Extract the actual file content from the diff
                file_content = extract_file_content_from_diff(diff_content, filename)
                
                if not file_content:
                    print(f"⚠️ Could not extract content for file: {filename}")
                    continue
                
                code_to_scan.append({"filename": filename, "content": file_content})
                print(f"✅ Prepared file for analysis: {filename}")

        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching code from API: {e}")
            return {
                "code_queue": [],
                "processed_files": [],
                "scan_results": [],
                "current_phase": "processing"
            }
        except json.JSONDecodeError:
            print("❌ Error: Failed to decode JSON from API response.")
            return {
                "code_queue": [],
                "processed_files": [],
                "scan_results": [],
                "current_phase": "processing"
            }

        if code_to_scan:
            print(f"✅ Fetched {len(code_to_scan)} code snippets from API to scan.")
        else:
            print("⚠️ No code found from the API endpoint.")

        return {
            "current_phase": "processing",
            "code_queue": code_to_scan,
            "processed_files": [],
            "scan_results": []
        }

    def extract_file_content_from_diff(diff_content: str, filename: str) -> str:
        """Extract the actual file content from a git diff."""
        lines = diff_content.split('\n')
        content_lines = []
        
        for line in lines:
            # Skip diff headers and metadata
            if line.startswith('diff --git') or line.startswith('index ') or line.startswith('---') or line.startswith('+++'):
                continue
            
            # Remove the diff markers and extract content
            if line.startswith('+') and not line.startswith('+++'):
                # This is an added line, include it
                content_lines.append(line[1:])
            elif line.startswith(' ') and not line.startswith(' '):
                # This is an unchanged line, include it
                content_lines.append(line[1:])
            # Skip lines starting with '-' as they are deletions
        
        return '\n'.join(content_lines)

    # MODIFIED: This agent now works with code content directly.
    async def code_processor_agent(state: SecurityAnalysisState):
        """Processes one code snippet from the queue, invoking tools to scan it."""
        print(f"--- PROCESSING PHASE (Queue size: {len(state['code_queue'])}) ---")
        code_queue = state.get("code_queue", [])
        
        if not code_queue:
            return {"current_phase": "reporting"}

        next_code_item = code_queue[0]
        remaining_queue = code_queue[1:]
        
        filename = next_code_item["filename"]
        code_content = next_code_item["content"]
        
        # Determine semgrep config from filename (logic is the same)
        file_ext = filename.split('.')[-1].lower()
        if file_ext in ['tf', 'tfvars']:
            config = 'p/terraform'
        elif file_ext in ['yml', 'yaml'] and ('k8s' in filename.lower() or 'kubernetes' in filename.lower()):
            config = 'p/kubernetes'
        elif 'dockerfile' in filename.lower():
            config = 'p/docker'
        else:
            config = 'p/default' # A generic, fast scan

        # MODIFIED: The prompt now includes the code and forbids filesystem access.
        scan_instruction = f"""
        You MUST perform a security scan on the following code from the file `{filename}`.

        CODE CONTENT:
        ```
        {code_content}
        ```

        MANDATORY INSTRUCTIONS:
        1. You MUST use the `semgrep_scan` tool directly on the code content provided above.
        2. Use the configuration: '{config}'.
        3. DO NOT use `read_text_file` or any other filesystem tool. You already have the code.
        4. Analyze the JSON output from semgrep and report any security findings in a human-readable format.

        YOU MUST call the `semgrep_scan` tool now.
        """
        
        response = await model_with_tools.ainvoke(state['messages'] + [("user", scan_instruction)])
        
        return {
            "messages": [response],
            "code_queue": remaining_queue,
            "processed_files": state.get("processed_files", []) + [filename],
            "scan_results": state.get("scan_results", [])
        }

    async def report_generator_agent(state: SecurityAnalysisState):
        """Generates a final summary report of all findings and sends to Slack."""
        print("--- REPORTING PHASE ---")
        
        # Safely get processed_files with a default empty list
        processed_files = state.get("processed_files", [])
        
        summary_prompt = (
            "You have completed the security scan. Please generate a final, comprehensive security report. "
            f"You have processed the following files: {processed_files}. "
            "Summarize all the findings from the conversation history, group them by severity, "
            "and provide clear recommendations for remediation."
        )
        response = await model.ainvoke(state['messages'] + [("user", summary_prompt)])
        report_content = response.content if hasattr(response, 'content') else str(response)
        formatted_report = format_security_report_for_slack(report_content)
        await send_to_slack(formatted_report)
        return {"messages": [response], "current_phase": "complete"}

    # MODIFIED: Router now checks the `code_queue`
    def processing_router(state: SecurityAnalysisState):
        """Determines the next step after the processor agent runs."""
        last_message = state["messages"][-1]
        
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "tools"
        
        if state.get("code_queue"): # Check the correct queue
            return "code_processor"
            
        return "report_generator"

    # --- Graph Construction ---
    builder = StateGraph(SecurityAnalysisState)
    
    builder.add_node("discovery", discovery_agent)
    builder.add_node("code_processor", code_processor_agent) # Renamed node for clarity
    builder.add_node("report_generator", report_generator_agent)
    if tool_node:
        builder.add_node("tools", tool_node)

    builder.add_edge(START, "discovery")
    builder.add_edge("discovery", "code_processor")

    builder.add_conditional_edges(
        "code_processor",
        processing_router,
        {
            "tools": "tools" if tool_node else "report_generator",
            "code_processor": "code_processor",
            "report_generator": "report_generator"
        }
    )
    
    if tool_node:
        builder.add_edge("tools", "code_processor") # Return to the processor after tool call

    builder.add_edge("report_generator", END)
    graph = builder.compile()

    # --- Graph Execution ---
    initial_prompt = "You are a security analysis AI agent. Your mission is to scan code for vulnerabilities. Let's begin."
    initial_state = { "messages": [("user", initial_prompt)] }
    
    final_state = await graph.ainvoke(initial_state, config={"recursion_limit": 50})
    
    print("\n--- FINAL REPORT ---")
    if final_state['messages'] and final_state['messages'][-1]:
         print(final_state['messages'][-1].content)

if __name__ == "__main__":
    asyncio.run(main())