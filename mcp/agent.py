import asyncio
import os
import requests
import json
from datetime import datetime
from langchain_mcp_adapters.client import MultiServerMCPClient
# Corrected import for the chat model
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, START, END
from typing import TypedDict, List
from typing_extensions import Annotated
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Slack integration functions
async def send_to_slack(message: str, webhook_url: str = None) -> bool:
    """Send security analysis report to Slack"""
    if not webhook_url:
        webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    
    if not webhook_url:
        print("⚠️ No Slack webhook URL found. Set SLACK_WEBHOOK_URL in .env file")
        return False
    
    try:
        # Format message for Slack
        slack_payload = {
            "text": "🔒 Security Analysis Report",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🔒 Security Analysis Report"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Timestamp:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Analysis Type:* Automated Security Scan"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"```\n{message}\n```"
                    }
                }
            ]
        }
        
        response = requests.post(
            webhook_url,
            json=slack_payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
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
    """Format the security report for better Slack presentation"""
    # Truncate if too long for Slack (max 3000 chars for text blocks)
    if len(report_content) > 2800:
        report_content = report_content[:2800] + "\n...\n[Report truncated - see full details in logs]"
    
    return report_content

# Define the state for the graph
# This structure correctly defines how messages and other data will be managed.
class SecurityAnalysisState(TypedDict):
    messages: Annotated[List, add_messages]
    file_queue: List[str]
    processed_files: List[str]
    scan_results: List[dict] # Note: This isn't currently being populated, but the field is ready.
    current_phase: str

async def main():
    # FIX 1: Correctly initialize the model using the standard LangChain class.
    # "gpt-4.1" is not a valid model name. Using a standard, powerful model like "gpt-4-turbo".
    # Setting temperature to 0 encourages more deterministic, instruction-following behavior.
    model = ChatOpenAI(model="gpt-4o", temperature=0)

    # Set up the Multi-Server MCP Client
    # Ensure the path "E:\\Threat_detect" exists and is accessible.
    client = MultiServerMCPClient(
        {
            "semgrep": {
                "url": "https://mcp.semgrep.ai/mcp",
                "transport": "streamable_http",
            },
            "filesystem": {
                "command": "npx",
                "args": [
                    "-y",
                    "@modelcontextprotocol/server-filesystem",
                    os.getcwd()  # Using the current working directory for portability
                ],
                "transport": "stdio",
            }
        }
    )
    
    # Gracefully load tools, allowing the script to run without them.
    try:
        tools = await client.get_tools()
        print("✅ MCP tools loaded successfully.")
    except Exception as e:
        print(f"⚠️ Warning: MCP tools failed to load ({str(e)}) – continuing without tools.")
        tools = []

    # Bind the loaded tools to the model.
    model_with_tools = model.bind_tools(tools) if tools else model
    tool_node = ToolNode(tools) if tools else None

    # --- Agent Definitions ---

    async def discovery_agent(state: SecurityAnalysisState):
        """Dynamically discovers all files within the 'threat-demo/IaC' subdirectory."""
        print("--- DISCOVERY PHASE ---")
    
        # Correctly point to the nested directory
        target_dir = os.path.join("threat-demo", "IaC")
        discovered_files = []
    
        if not os.path.isdir(target_dir):
            print(f"⚠️ Error: Directory '{target_dir}' not found. Make sure you are running the script from the correct location.")
            return {
                "file_queue": [],
            }

        # os.walk will find all files in the target directory and its subfolders
        for root, _, files in os.walk(target_dir):
            for filename in files:
                # Create the full relative path (e.g., "threat-demo/IaC/terraform/main.tf")
                full_path = os.path.join(root, filename)
                discovered_files.append(full_path)
                
        if discovered_files:
            print(f"✅ Discovered {len(discovered_files)} files to scan: {discovered_files}")
        else:
            print(f"⚠️ No files found in the '{target_dir}' directory.")

        return {
            "current_phase": "processing",
            "file_queue": discovered_files,
            "processed_files": [],
            "scan_results": []
        }

    async def file_processor_agent(state: SecurityAnalysisState):
        """Processes one file from the queue, invoking tools to scan it."""
        print(f"--- PROCESSING PHASE (Queue: {state['file_queue']}) ---")
        file_queue = state.get("file_queue", [])
        
        if not file_queue:
            # This case should ideally not be hit due to graph routing, but it's safe to have.
            return {"current_phase": "reporting"}

        next_file = file_queue[0]
        remaining_queue = file_queue[1:]
        
        # Dynamically create the prompt based on the file type
        file_ext = next_file.split('.')[-1].lower()
        if file_ext in ['tf', 'tfvars']:
            config = 'p/terraform'
        elif file_ext in ['yml', 'yaml'] and 'k8s' in next_file.lower():
            config = 'p/kubernetes'
        elif 'dockerfile' in next_file.lower():
            config = 'p/docker'
        else:
            # Default to a generic, fast scan for other file types
            config = 'p/default'

        scan_instruction = f"""
        You MUST perform a security scan on the file: `{next_file}`.
        
        Follow these steps MANDATORILY:
        1. Use the `read_text_file` tool to read the content of `{next_file}`.
        2. Use the `semgrep_scan` tool on the content you just read. Use the configuration: '{config}'.
        3. Analyze the JSON output from semgrep and report any security findings in a human-readable format.
        
        DO NOT describe what you would do. YOU MUST call the tools now.
        """
        
        # Append the instruction to the message history and invoke the model
        response = await model_with_tools.ainvoke(state['messages'] + [("user", scan_instruction)])
        
        return {
            "messages": [response],
            "file_queue": remaining_queue,
            "processed_files": state.get("processed_files", []) + [next_file],
        }

    async def report_generator_agent(state: SecurityAnalysisState):
        """Generates a final summary report of all findings and sends to Slack."""
        print("--- REPORTING PHASE ---")
        summary_prompt = (
            "You have completed the security scan. Please generate a final, comprehensive security report. "
            f"You have processed the following files: {state['processed_files']}. "
            "Summarize all the findings from the conversation history, group them by severity, "
            "and provide clear recommendations for remediation."
        )
        response = await model.ainvoke(state['messages'] + [("user", summary_prompt)])
        
        # Extract the report content
        report_content = response.content if hasattr(response, 'content') else str(response)
        
        # Format and send to Slack
        formatted_report = format_security_report_for_slack(report_content)
        slack_success = await send_to_slack(formatted_report)
        
        if slack_success:
            print("📤 Security report sent to Slack!")
        else:
            print("📋 Security report generated (Slack delivery failed)")
        
        return {"messages": [response], "current_phase": "complete"}

    # --- Graph Routing Logic ---

    # FIX 2: A simplified and more robust router function.
    # This function is now only responsible for the logic within the processing loop.
    def processing_router(state: SecurityAnalysisState):
        """Determines the next step after the file_processor_agent runs."""
        last_message = state["messages"][-1]
        
        # If the last message from the agent contains a tool call, route to the tool node.
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "tools"
        
        # If there are still files in the queue, loop back to the processor.
        if state.get("file_queue"):
            return "file_processor"
            
        # If the queue is empty, proceed to generate the final report.
        return "report_generator"

    # --- Graph Construction ---

    builder = StateGraph(SecurityAnalysisState)
    
    # Add all the nodes to the graph
    builder.add_node("discovery", discovery_agent)
    builder.add_node("file_processor", file_processor_agent)
    builder.add_node("report_generator", report_generator_agent)
    if tool_node:
        builder.add_node("tools", tool_node)

    # FIX 3: Simplified and more robust graph edges.
    # The workflow is now more explicit and easier to follow.
    builder.add_edge(START, "discovery")
    builder.add_edge("discovery", "file_processor")

    # The file_processor is the heart of the loop. Its next step is conditional.
    builder.add_conditional_edges(
        "file_processor",
        processing_router,
        # The dictionary maps the router's return values to the next node.
        {
            "tools": "tools" if tool_node else "report_generator", # Fallback if tools aren't loaded
            "file_processor": "file_processor",
            "report_generator": "report_generator"
        }
    )
    
    # CRITICAL FIX: After a tool is used, control MUST return to the agent that called it
    # so it can process the results. We add a direct edge back to the file_processor.
    if tool_node:
        builder.add_edge("tools", "file_processor")

    # The report generator is the final step before ending.
    builder.add_edge("report_generator", END)

    graph = builder.compile()

    # --- Graph Execution ---
    
    # The initial prompt provides the agent with its persona and overall goal.
    initial_prompt = """
    You are a security analysis AI agent. Your mission is to scan code for vulnerabilities using the provided tools.
    Start by analyzing the files given to you one by one. After scanning all files, provide a final summary report.
    Let's begin the analysis.
    """
    initial_state = {
        "messages": [("user", initial_prompt)],
    }
    
    # Invoke the graph with the initial state
    final_state = await graph.ainvoke(initial_state, config={"recursion_limit": 20})
    
    print("\n--- FINAL REPORT ---")
    # Print the last message from the AI, which contains the final report.
    print(final_state['messages'][-1].content)


if __name__ == "__main__":
    # To run this, you need a file named `vuln_sample.py` in the same directory.
    # Example `vuln_sample.py`:
    # import os
    # password = "hardcoded_password"
    # def run_command(cmd):
    #     os.system(f"echo {cmd}")
    asyncio.run(main())