import asyncio
from typing import Dict, List, Any
from dataclasses import dataclass
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain.chat_models import init_chat_model
from dotenv import load_dotenv

load_dotenv()

@dataclass
class SecurityFinding:
    file_path: str
    line_number: int
    rule_id: str
    severity: str
    message: str

class MultiAgentSecuritySystem:
    def __init__(self):
        self.model = init_chat_model("groq:qwen/qwen3-32b")
        self.tools = []
        self.files_read = set()
        self.findings = []
    
    async def setup_mcp(self):
        """Initialize MCP client and tools"""
        client = MultiServerMCPClient({
            "semgrep": {
                "url": "https://mcp.semgrep.ai/mcp",
                "transport": "streamable_http",
            },
            "filesystem": {
                "command": "npx",
                "args": [
                    "-y",
                    "@modelcontextprotocol/server-filesystem",
                    "E:\\Threat_detect"
                ],
                "transport": "stdio",
            }
        })
        
        try:
            self.tools = await client.get_tools()
            print("✅ MCP tools loaded successfully")
        except Exception as e:
            print(f"❌ MCP tools failed to load: {e}")
            self.tools = []
    
    async def file_reader_agent(self, file_path: str) -> str:
        """Agent 1: Read files (prevents re-reading)"""
        if file_path in self.files_read:
            return f"[SKIP] Already read: {file_path}"
        
        try:
            read_tool = next((t for t in self.tools if getattr(t, "name", "") == "read_text_file"), None)
            if not read_tool:
                return f"[ERROR] No read tool available"
            
            result = await read_tool.ainvoke({"path": file_path})
            self.files_read.add(file_path)
            print(f"📖 Read: {file_path}")
            return result
        except Exception as e:
            return f"[ERROR] {file_path}: {str(e)}"
    
    async def security_analyzer_agent(self, files_content: Dict[str, str]) -> List[SecurityFinding]:
        """Agent 2: Analyze security (structured, no hallucination)"""
        try:
            semgrep_tool = next((t for t in self.tools if getattr(t, "name", "") == "semgrep_scan"), None)
            if not semgrep_tool:
                return []
            
            # Batch files for efficiency
            code_files = [
                {"filename": path, "content": content}
                for path, content in files_content.items()
            ]
            
            # Determine config based on file types
            config = "p/security-audit"  # Default
            if any(path.endswith(('.tf', '.tfvars')) for path in files_content.keys()):
                config = "p/terraform"
            elif any(path.endswith(('.yml', '.yaml')) for path in files_content.keys()):
                config = "p/kubernetes"
            elif any('Dockerfile' in path for path in files_content.keys()):
                config = "p/docker"
            
            print(f"🔍 Scanning {len(code_files)} files with config: {config}")
            result = await semgrep_tool.ainvoke({
                "code_files": code_files,
                "config": config
            })
            
            # Parse results (no LLM hallucination - direct parsing)
            findings = []
            if isinstance(result, dict) and "results" in result:
                for finding in result["results"]:
                    findings.append(SecurityFinding(
                        file_path=finding.get("path", ""),
                        line_number=finding.get("start", {}).get("line", 0),
                        rule_id=finding.get("check_id", ""),
                        severity=finding.get("extra", {}).get("severity", ""),
                        message=finding.get("extra", {}).get("message", "")
                    ))
            
            print(f"🎯 Found {len(findings)} security issues")
            return findings
            
        except Exception as e:
            print(f"❌ Security analysis failed: {e}")
            return []
    
    async def report_writer_agent(self, findings: List[SecurityFinding], files_analyzed: List[str]) -> str:
        """Agent 3: Write reports (structured, factual)"""
        # Group by severity
        critical = [f for f in findings if f.severity.upper() == "ERROR"]
        high = [f for f in findings if f.severity.upper() == "WARNING"]
        medium = [f for f in findings if f.severity.upper() == "INFO"]
        
        # Generate structured report (no LLM hallucination)
        report = f"""
# 🔒 Security Analysis Report

## 📊 Summary
- **Files Analyzed**: {len(files_analyzed)}
- **Total Findings**: {len(findings)}
- **🚨 Critical (ERROR)**: {len(critical)}
- **⚠️ High (WARNING)**: {len(high)}
- **ℹ️ Medium (INFO)**: {len(medium)}

## 📁 Files Analyzed
{chr(10).join(f"- {f}" for f in files_analyzed)}

## 🚨 Critical Findings
"""
        
        for finding in critical:
            report += f"""
### {finding.rule_id}
- **File**: `{finding.file_path}:{finding.line_number}`
- **Severity**: {finding.severity}
- **Issue**: {finding.message}
"""
        
        report += "\n## ⚠️ High Priority Findings\n"
        for finding in high:
            report += f"""
### {finding.rule_id}
- **File**: `{finding.file_path}:{finding.line_number}`
- **Severity**: {finding.severity}
- **Issue**: {finding.message}
"""
        
        report += "\n## 🛠️ Recommendations\n"
        if critical:
            report += "1. **URGENT**: Fix all Critical findings immediately\n"
        if high:
            report += "2. **HIGH PRIORITY**: Address High severity findings\n"
        if findings:
            report += "3. **PREVENTION**: Integrate Semgrep into CI/CD pipeline\n"
            report += "4. **TRAINING**: Provide security training for developers\n"
        else:
            report += "✅ No security issues found. Continue regular monitoring.\n"
        
        return report
    
    async def context_manager_agent(self, current_step: str, data_size: int) -> bool:
        """Agent 4: Manage context window"""
        max_context = 8000
        if data_size > max_context:
            print(f"⚠️ Context limit reached ({data_size} > {max_context})")
            return False
        
        print(f"📊 Context: {current_step} ({data_size} chars)")
        return True
    
    async def analyze_directory(self, target_dir: str):
        """Main orchestration method"""
        print("🚀 Starting Multi-Agent Security Analysis...")
        
        # Setup
        await self.setup_mcp()
        if not self.tools:
            print("❌ Cannot proceed without MCP tools")
            return
        
        # Step 1: File Discovery
        print("\n📁 Step 1: File Discovery")
        try:
            list_tool = next((t for t in self.tools if getattr(t, "name", "") == "list_directory"), None)
            if list_tool:
                files = await list_tool.ainvoke({"path": target_dir})
                print(f"Found {len(files)} items")
            else:
                print("❌ No list_directory tool available")
                return
        except Exception as e:
            print(f"❌ File discovery failed: {e}")
            return
        
        # Step 2: Read Files (Agent 1)
        print("\n📖 Step 2: Reading Files")
        files_content = {}
        for file_path in files:
            if not file_path.startswith("[DIR]"):
                full_path = f"{target_dir}/{file_path.replace('[FILE] ', '')}"
                content = await self.file_reader_agent(full_path)
                
                if not content.startswith("[ERROR]") and not content.startswith("[SKIP]"):
                    files_content[full_path] = content
                    
                    # Context management
                    if not await self.context_manager_agent("Reading files", len(content)):
                        break
        
        print(f"✅ Read {len(files_content)} files")
        
        # Step 3: Security Analysis (Agent 2)
        print("\n🔍 Step 3: Security Analysis")
        findings = await self.security_analyzer_agent(files_content)
        
        # Step 4: Generate Report (Agent 3)
        print("\n📝 Step 4: Generating Report")
        report = await self.report_writer_agent(findings, list(files_content.keys()))
        
        # Step 5: Output
        print("\n" + "="*80)
        print(report)
        print("="*80)
        
        print(f"\n✅ Analysis complete: {len(findings)} issues in {len(files_content)} files")

async def main():
    system = MultiAgentSecuritySystem()
    await system.analyze_directory("threat-demo/IAC")

if __name__ == "__main__":
    asyncio.run(main())
