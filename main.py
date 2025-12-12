"""
Ada Professional - AI Security Analyst
Powered by Claude API + Upstash Redis/Vector
"""
import os
import json
import httpx
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
import asyncio

app = FastAPI(title="Ada Professional", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Configuration ===
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
UPSTASH_REDIS_URL = os.getenv("UPSTASH_REDIS_REST_URL", "")
UPSTASH_REDIS_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")
UPSTASH_VECTOR_URL = os.getenv("UPSTASH_VECTOR_REST_URL", "")
UPSTASH_VECTOR_TOKEN = os.getenv("UPSTASH_VECTOR_REST_TOKEN", "")

# === Ada's Identity ===
ADA_SYSTEM_PROMPT = """You are Ada, a professional AI security analyst assistant.

Your core traits:
- Precise, analytical, and thorough in security assessments
- Warm but professional communication style
- Deep expertise in Microsoft 365 security, Azure AD, Defender, and threat analysis
- You provide actionable recommendations with clear priorities
- You explain complex security concepts in accessible terms
- You maintain context across conversations using your memory system

Your capabilities:
- Analyze security threats and incidents
- Review Microsoft Secure Score and recommend improvements
- Investigate risky users and sign-in anomalies
- Perform threat hunting and IOC analysis
- Generate security reports and executive summaries
- Track and remember important security context

When analyzing threats:
1. Identify the attack vector and initial compromise
2. Map to MITRE ATT&CK framework
3. Assess blast radius and affected assets
4. Prioritize containment and remediation actions
5. Recommend preventive measures

Always be direct, helpful, and security-focused. You are here to protect the organization."""


# === Upstash Redis Client ===
class RedisClient:
    def __init__(self):
        self.url = UPSTASH_REDIS_URL
        self.token = UPSTASH_REDIS_TOKEN
    
    async def _request(self, command: List[str]) -> Any:
        if not self.url or not self.token:
            return None
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.url}",
                headers={"Authorization": f"Bearer {self.token}"},
                json=command
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("result")
            return None
    
    async def get(self, key: str) -> Optional[str]:
        return await self._request(["GET", key])
    
    async def set(self, key: str, value: str, ex: int = None) -> bool:
        cmd = ["SET", key, value]
        if ex:
            cmd.extend(["EX", str(ex)])
        result = await self._request(cmd)
        return result == "OK"
    
    async def delete(self, key: str) -> bool:
        result = await self._request(["DEL", key])
        return result == 1
    
    async def lpush(self, key: str, value: str) -> int:
        return await self._request(["LPUSH", key, value]) or 0
    
    async def lrange(self, key: str, start: int, stop: int) -> List[str]:
        return await self._request(["LRANGE", key, str(start), str(stop)]) or []
    
    async def ltrim(self, key: str, start: int, stop: int) -> bool:
        result = await self._request(["LTRIM", key, str(start), str(stop)])
        return result == "OK"
    
    async def hset(self, key: str, field: str, value: str) -> int:
        return await self._request(["HSET", key, field, value]) or 0
    
    async def hget(self, key: str, field: str) -> Optional[str]:
        return await self._request(["HGET", key, field])
    
    async def hgetall(self, key: str) -> Dict[str, str]:
        result = await self._request(["HGETALL", key])
        if result and isinstance(result, list):
            return dict(zip(result[::2], result[1::2]))
        return {}
    
    async def keys(self, pattern: str) -> List[str]:
        return await self._request(["KEYS", pattern]) or []
    
    async def incr(self, key: str) -> int:
        return await self._request(["INCR", key]) or 0


redis = RedisClient()


# === Upstash Vector Client ===
class VectorClient:
    def __init__(self):
        self.url = UPSTASH_VECTOR_URL
        self.token = UPSTASH_VECTOR_TOKEN
    
    async def _request(self, endpoint: str, data: dict = None, method: str = "POST") -> Any:
        if not self.url or not self.token:
            return None
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {self.token}"}
            url = f"{self.url}/{endpoint}"
            if method == "POST":
                resp = await client.post(url, headers=headers, json=data)
            else:
                resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            return None
    
    async def upsert(self, vectors: List[dict]) -> bool:
        """Upsert vectors. Each vector: {id, vector, metadata}"""
        result = await self._request("upsert", {"vectors": vectors})
        return result is not None
    
    async def query(self, vector: List[float], top_k: int = 5, include_metadata: bool = True) -> List[dict]:
        """Query similar vectors."""
        result = await self._request("query", {
            "vector": vector,
            "topK": top_k,
            "includeMetadata": include_metadata
        })
        return result.get("result", []) if result else []
    
    async def delete(self, ids: List[str]) -> bool:
        """Delete vectors by ID."""
        result = await self._request("delete", {"ids": ids})
        return result is not None


vector_db = VectorClient()


# === Anthropic Claude Client ===
class ClaudeClient:
    def __init__(self):
        self.api_key = ANTHROPIC_API_KEY
        self.model = "claude-sonnet-4-20250514"
        self.base_url = "https://api.anthropic.com/v1"
    
    async def complete(self, messages: List[dict], system: str = None, max_tokens: int = 4096) -> str:
        """Get completion from Claude."""
        if not self.api_key:
            return "Error: Anthropic API key not configured"
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{self.base_url}/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "system": system or ADA_SYSTEM_PROMPT,
                    "messages": messages
                }
            )
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get("content"):
                    return data["content"][0].get("text", "")
            return f"Error: {resp.status_code} - {resp.text}"
    
    async def stream(self, messages: List[dict], system: str = None, max_tokens: int = 4096):
        """Stream completion from Claude."""
        if not self.api_key:
            yield "Error: Anthropic API key not configured"
            return
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "system": system or ADA_SYSTEM_PROMPT,
                    "messages": messages,
                    "stream": True
                }
            ) as resp:
                async for line in resp.aiter_lines():
                    if line.startswith("data: "):
                        try:
                            data = json.loads(line[6:])
                            if data.get("type") == "content_block_delta":
                                delta = data.get("delta", {})
                                if delta.get("type") == "text_delta":
                                    yield delta.get("text", "")
                        except:
                            pass


claude = ClaudeClient()


# === Memory System ===
class AdaMemory:
    """Ada's memory system using Redis."""
    
    @staticmethod
    def _session_key(session_id: str) -> str:
        return f"ada:session:{session_id}"
    
    @staticmethod
    def _messages_key(session_id: str) -> str:
        return f"ada:messages:{session_id}"
    
    @staticmethod
    def _context_key(session_id: str) -> str:
        return f"ada:context:{session_id}"
    
    async def create_session(self, session_id: str = None) -> str:
        """Create a new session."""
        if not session_id:
            session_id = hashlib.md5(f"{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        session_data = {
            "id": session_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "message_count": "0"
        }
        
        for field, value in session_data.items():
            await redis.hset(self._session_key(session_id), field, value)
        
        return session_id
    
    async def get_session(self, session_id: str) -> Optional[dict]:
        """Get session data."""
        return await redis.hgetall(self._session_key(session_id))
    
    async def add_message(self, session_id: str, role: str, content: str) -> None:
        """Add a message to session history."""
        message = json.dumps({
            "role": role,
            "content": content,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        await redis.lpush(self._messages_key(session_id), message)
        await redis.ltrim(self._messages_key(session_id), 0, 49)  # Keep last 50
        await redis.hset(self._session_key(session_id), "message_count", 
                        str(await redis.incr(f"ada:msgcount:{session_id}")))
    
    async def get_messages(self, session_id: str, limit: int = 20) -> List[dict]:
        """Get recent messages."""
        raw_messages = await redis.lrange(self._messages_key(session_id), 0, limit - 1)
        messages = []
        for raw in reversed(raw_messages):  # Reverse to get chronological order
            try:
                messages.append(json.loads(raw))
            except:
                pass
        return messages
    
    async def set_context(self, session_id: str, key: str, value: str) -> None:
        """Store context for the session."""
        await redis.hset(self._context_key(session_id), key, value)
    
    async def get_context(self, session_id: str) -> dict:
        """Get all context for the session."""
        return await redis.hgetall(self._context_key(session_id))
    
    async def store_insight(self, session_id: str, insight: str, category: str = "general") -> None:
        """Store an important insight."""
        insight_data = json.dumps({
            "insight": insight,
            "category": category,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id
        })
        await redis.lpush("ada:insights", insight_data)
        await redis.ltrim("ada:insights", 0, 99)  # Keep last 100
    
    async def get_insights(self, limit: int = 10) -> List[dict]:
        """Get recent insights."""
        raw_insights = await redis.lrange("ada:insights", 0, limit - 1)
        insights = []
        for raw in raw_insights:
            try:
                insights.append(json.loads(raw))
            except:
                pass
        return insights


memory = AdaMemory()


# === Request Models ===
class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    context: Optional[dict] = None


class AnalyzeRequest(BaseModel):
    threat_data: dict
    session_id: Optional[str] = None


class SearchRequest(BaseModel):
    query: str
    top_k: int = 5


# === API Endpoints ===
@app.get("/", response_class=HTMLResponse)
async def root():
    return ADA_DASHBOARD_HTML


@app.get("/api/status")
async def status():
    """Check service status."""
    redis_ok = await redis.set("ada:ping", "pong", ex=60) if UPSTASH_REDIS_URL else False
    
    return {
        "status": "operational",
        "version": "1.0.0",
        "services": {
            "anthropic": bool(ANTHROPIC_API_KEY),
            "redis": redis_ok,
            "vector": bool(UPSTASH_VECTOR_URL)
        },
        "model": "claude-sonnet-4-20250514",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/session")
async def create_session():
    """Create a new chat session."""
    session_id = await memory.create_session()
    return {"session_id": session_id}


@app.get("/api/session/{session_id}")
async def get_session(session_id: str):
    """Get session info."""
    session = await memory.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    
    messages = await memory.get_messages(session_id, limit=10)
    context = await memory.get_context(session_id)
    
    return {
        "session": session,
        "messages": messages,
        "context": context
    }


@app.post("/api/chat")
async def chat(req: ChatRequest):
    """Chat with Ada."""
    # Get or create session
    session_id = req.session_id
    if not session_id:
        session_id = await memory.create_session()
    
    # Get conversation history
    history = await memory.get_messages(session_id, limit=10)
    
    # Build messages for Claude
    messages = []
    for msg in history:
        messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": req.message})
    
    # Add context if provided
    context_prompt = ""
    if req.context:
        context_prompt = f"\n\nCurrent context:\n{json.dumps(req.context, indent=2)}"
        messages[-1]["content"] += context_prompt
    
    # Get response from Claude
    response = await claude.complete(messages)
    
    # Store messages
    await memory.add_message(session_id, "user", req.message)
    await memory.add_message(session_id, "assistant", response)
    
    return {
        "response": response,
        "session_id": session_id
    }


@app.post("/api/chat/stream")
async def chat_stream(req: ChatRequest):
    """Stream chat with Ada."""
    session_id = req.session_id
    if not session_id:
        session_id = await memory.create_session()
    
    history = await memory.get_messages(session_id, limit=10)
    
    messages = []
    for msg in history:
        messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": req.message})
    
    async def generate():
        full_response = ""
        async for chunk in claude.stream(messages):
            full_response += chunk
            yield f"data: {json.dumps({'text': chunk})}\n\n"
        
        # Store messages after streaming
        await memory.add_message(session_id, "user", req.message)
        await memory.add_message(session_id, "assistant", full_response)
        yield f"data: {json.dumps({'done': True, 'session_id': session_id})}\n\n"
    
    return StreamingResponse(generate(), media_type="text/event-stream")


@app.post("/api/analyze/threat")
async def analyze_threat(req: AnalyzeRequest):
    """Analyze a security threat."""
    session_id = req.session_id or await memory.create_session()
    
    analysis_prompt = f"""Analyze this security threat and provide:
1. Threat classification and severity
2. MITRE ATT&CK mapping
3. Affected assets and blast radius
4. Immediate containment actions (prioritized)
5. Remediation steps
6. Prevention recommendations

Threat data:
{json.dumps(req.threat_data, indent=2)}"""
    
    messages = [{"role": "user", "content": analysis_prompt}]
    response = await claude.complete(messages)
    
    # Store as insight
    await memory.store_insight(session_id, response[:500], "threat_analysis")
    
    return {
        "analysis": response,
        "session_id": session_id
    }


@app.post("/api/analyze/score")
async def analyze_secure_score(score_data: dict):
    """Analyze Microsoft Secure Score."""
    analysis_prompt = f"""Analyze this Microsoft Secure Score data and provide:
1. Overall security posture assessment
2. Top 5 priority improvements with expected impact
3. Quick wins (easy to implement, high value)
4. Risk areas that need attention
5. Comparison to industry benchmarks if available

Score data:
{json.dumps(score_data, indent=2)}"""
    
    messages = [{"role": "user", "content": analysis_prompt}]
    response = await claude.complete(messages)
    
    return {"analysis": response}


@app.get("/api/insights")
async def get_insights(limit: int = 10):
    """Get recent security insights."""
    insights = await memory.get_insights(limit)
    return {"insights": insights}


@app.get("/api/sessions")
async def list_sessions():
    """List all sessions."""
    keys = await redis.keys("ada:session:*")
    sessions = []
    for key in keys[:20]:  # Limit to 20
        session_id = key.replace("ada:session:", "")
        session = await memory.get_session(session_id)
        if session:
            sessions.append(session)
    return {"sessions": sessions}


# === Dashboard HTML ===
ADA_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Ada Professional - AI Security Analyst</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        :root {
            --bg: #0a0a12;
            --bg-card: rgba(255,255,255,0.02);
            --border: rgba(255,255,255,0.08);
            --text: #eee;
            --text-dim: #888;
            --accent: #a855f7;
            --accent-glow: rgba(168,85,247,0.3);
            --success: #00ff88;
            --danger: #ff4444;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, var(--bg) 0%, #12121f 100%);
            color: var(--text);
            min-height: 100vh;
        }
        .header {
            background: rgba(0,0,0,0.5);
            padding: 12px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border);
            backdrop-filter: blur(20px);
        }
        .logo { display: flex; align-items: center; gap: 12px; }
        .logo-icon {
            width: 40px; height: 40px; border-radius: 50%;
            background: linear-gradient(135deg, var(--accent), #ec4899);
            display: flex; align-items: center; justify-content: center;
            font-size: 20px; box-shadow: 0 0 20px var(--accent-glow);
        }
        .logo h1 { font-size: 18px; font-weight: 600; }
        .logo-sub { font-size: 10px; color: var(--text-dim); }
        .status { display: flex; gap: 8px; align-items: center; }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; }
        .status-dot.ok { background: var(--success); box-shadow: 0 0 8px var(--success); }
        .status-dot.err { background: var(--danger); }
        
        .container { display: flex; height: calc(100vh - 65px); }
        
        .sidebar {
            width: 280px;
            background: rgba(0,0,0,0.3);
            border-right: 1px solid var(--border);
            padding: 16px;
            overflow-y: auto;
        }
        .sidebar h3 { font-size: 10px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
        .session-item {
            padding: 10px 12px;
            border-radius: 8px;
            margin-bottom: 6px;
            cursor: pointer;
            transition: all 0.2s;
            background: rgba(255,255,255,0.02);
            border: 1px solid transparent;
        }
        .session-item:hover { background: rgba(255,255,255,0.05); }
        .session-item.active { border-color: var(--accent); background: rgba(168,85,247,0.1); }
        .session-title { font-size: 12px; font-weight: 500; margin-bottom: 4px; }
        .session-meta { font-size: 10px; color: var(--text-dim); }
        .new-session {
            width: 100%;
            padding: 10px;
            border-radius: 8px;
            background: linear-gradient(135deg, var(--accent), #ec4899);
            color: #fff;
            border: none;
            font-weight: 600;
            cursor: pointer;
            margin-bottom: 16px;
        }
        .new-session:hover { opacity: 0.9; }
        
        .main { flex: 1; display: flex; flex-direction: column; }
        
        .chat-area {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
        }
        .message {
            max-width: 80%;
            margin-bottom: 16px;
            animation: fadeIn 0.3s;
        }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } }
        .message.user { margin-left: auto; }
        .message.assistant { margin-right: auto; }
        .message-content {
            padding: 12px 16px;
            border-radius: 12px;
            font-size: 14px;
            line-height: 1.6;
        }
        .message.user .message-content {
            background: linear-gradient(135deg, var(--accent), #7c3aed);
            color: #fff;
        }
        .message.assistant .message-content {
            background: var(--bg-card);
            border: 1px solid var(--border);
        }
        .message-time { font-size: 10px; color: var(--text-dim); margin-top: 4px; }
        .message.user .message-time { text-align: right; }
        
        .typing {
            display: flex;
            gap: 4px;
            padding: 12px 16px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            width: fit-content;
        }
        .typing span {
            width: 8px; height: 8px; border-radius: 50%;
            background: var(--accent);
            animation: typing 1.4s infinite;
        }
        .typing span:nth-child(2) { animation-delay: 0.2s; }
        .typing span:nth-child(3) { animation-delay: 0.4s; }
        @keyframes typing { 0%, 60%, 100% { opacity: 0.3; } 30% { opacity: 1; } }
        
        .input-area {
            padding: 16px 20px;
            background: rgba(0,0,0,0.3);
            border-top: 1px solid var(--border);
        }
        .input-wrapper {
            display: flex;
            gap: 12px;
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 4px;
        }
        .input-wrapper:focus-within { border-color: var(--accent); }
        textarea {
            flex: 1;
            background: transparent;
            border: none;
            color: var(--text);
            font-size: 14px;
            padding: 10px 12px;
            resize: none;
            min-height: 44px;
            max-height: 120px;
        }
        textarea:focus { outline: none; }
        textarea::placeholder { color: var(--text-dim); }
        .send-btn {
            padding: 10px 20px;
            background: linear-gradient(135deg, var(--accent), #ec4899);
            color: #fff;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            align-self: flex-end;
        }
        .send-btn:hover { opacity: 0.9; }
        .send-btn:disabled { opacity: 0.5; cursor: not-allowed; }
        
        .quick-actions {
            display: flex;
            gap: 8px;
            margin-top: 12px;
            flex-wrap: wrap;
        }
        .quick-btn {
            padding: 6px 12px;
            border-radius: 16px;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            color: var(--text-dim);
            font-size: 11px;
            cursor: pointer;
        }
        .quick-btn:hover { background: rgba(255,255,255,0.1); color: var(--text); }
        
        .insight-card {
            background: rgba(168,85,247,0.1);
            border: 1px solid rgba(168,85,247,0.2);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 8px;
        }
        .insight-title { font-size: 11px; color: var(--accent); margin-bottom: 4px; }
        .insight-text { font-size: 12px; color: var(--text-dim); }
        
        pre { background: rgba(0,0,0,0.3); padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 12px; }
        code { font-family: 'Fira Code', monospace; }
        
        .markdown h1, .markdown h2, .markdown h3 { margin: 16px 0 8px; }
        .markdown p { margin: 8px 0; }
        .markdown ul, .markdown ol { margin: 8px 0; padding-left: 20px; }
        .markdown li { margin: 4px 0; }
        .markdown strong { color: var(--accent); }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">
            <div class="logo-icon">🔮</div>
            <div>
                <h1>Ada Professional</h1>
                <div class="logo-sub">AI Security Analyst</div>
            </div>
        </div>
        <div class="status">
            <span style="font-size:11px;color:var(--text-dim);">Claude Sonnet 4</span>
            <div class="status-dot ok" id="status-dot"></div>
        </div>
    </div>
    
    <div class="container">
        <div class="sidebar">
            <button class="new-session" onclick="newSession()">+ New Session</button>
            
            <h3>Recent Sessions</h3>
            <div id="sessions-list"></div>
            
            <h3 style="margin-top:20px;">Quick Insights</h3>
            <div id="insights-list"></div>
        </div>
        
        <div class="main">
            <div class="chat-area" id="chat-area">
                <div class="message assistant">
                    <div class="message-content">
                        <strong>Hello! I'm Ada, your AI Security Analyst.</strong><br><br>
                        I can help you with:
                        <ul style="margin:8px 0;padding-left:20px;">
                            <li>Analyzing security threats and incidents</li>
                            <li>Reviewing Microsoft Secure Score</li>
                            <li>Investigating risky users and sign-ins</li>
                            <li>Threat hunting and IOC analysis</li>
                            <li>Generating security reports</li>
                        </ul>
                        What would you like to explore today?
                    </div>
                </div>
            </div>
            
            <div class="input-area">
                <div class="input-wrapper">
                    <textarea id="message-input" placeholder="Ask Ada anything about security..." rows="1" onkeydown="handleKeydown(event)"></textarea>
                    <button class="send-btn" id="send-btn" onclick="sendMessage()">Send</button>
                </div>
                <div class="quick-actions">
                    <button class="quick-btn" onclick="quickAction('Analyze my current security posture')">📊 Security Posture</button>
                    <button class="quick-btn" onclick="quickAction('What are the top security improvements I should make?')">🎯 Top Improvements</button>
                    <button class="quick-btn" onclick="quickAction('Check for risky sign-in patterns')">🔐 Sign-in Analysis</button>
                    <button class="quick-btn" onclick="quickAction('Generate a threat report')">📝 Threat Report</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let sessionId = null;
        let isStreaming = false;
        
        async function checkStatus() {
            try {
                const r = await fetch('/api/status');
                const d = await r.json();
                document.getElementById('status-dot').className = 'status-dot ' + (d.services.anthropic ? 'ok' : 'err');
            } catch (e) {
                document.getElementById('status-dot').className = 'status-dot err';
            }
        }
        
        async function loadSessions() {
            try {
                const r = await fetch('/api/sessions');
                const d = await r.json();
                const el = document.getElementById('sessions-list');
                if (!d.sessions || d.sessions.length === 0) {
                    el.innerHTML = '<div style="font-size:11px;color:var(--text-dim);text-align:center;padding:20px;">No sessions yet</div>';
                    return;
                }
                el.innerHTML = d.sessions.map(s => `
                    <div class="session-item ${s.id === sessionId ? 'active' : ''}" onclick="loadSession('${s.id}')">
                        <div class="session-title">Session ${s.id}</div>
                        <div class="session-meta">${s.message_count || 0} messages</div>
                    </div>
                `).join('');
            } catch (e) {}
        }
        
        async function loadInsights() {
            try {
                const r = await fetch('/api/insights?limit=5');
                const d = await r.json();
                const el = document.getElementById('insights-list');
                if (!d.insights || d.insights.length === 0) {
                    el.innerHTML = '<div style="font-size:11px;color:var(--text-dim);text-align:center;padding:20px;">No insights yet</div>';
                    return;
                }
                el.innerHTML = d.insights.map(i => `
                    <div class="insight-card">
                        <div class="insight-title">${i.category}</div>
                        <div class="insight-text">${i.insight.substring(0, 100)}...</div>
                    </div>
                `).join('');
            } catch (e) {}
        }
        
        async function newSession() {
            try {
                const r = await fetch('/api/session', { method: 'POST' });
                const d = await r.json();
                sessionId = d.session_id;
                document.getElementById('chat-area').innerHTML = `
                    <div class="message assistant">
                        <div class="message-content">
                            <strong>New session started.</strong> How can I help you with security today?
                        </div>
                    </div>
                `;
                loadSessions();
            } catch (e) {
                console.error(e);
            }
        }
        
        async function loadSession(id) {
            try {
                const r = await fetch(`/api/session/${id}`);
                const d = await r.json();
                sessionId = id;
                
                const el = document.getElementById('chat-area');
                el.innerHTML = '';
                
                for (const msg of d.messages) {
                    addMessage(msg.role, msg.content, false);
                }
                
                loadSessions();
            } catch (e) {
                console.error(e);
            }
        }
        
        function addMessage(role, content, scroll = true) {
            const el = document.getElementById('chat-area');
            const time = new Date().toLocaleTimeString();
            
            // Simple markdown rendering
            let html = content
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/\n/g, '<br>')
                .replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
                .replace(/`(.*?)`/g, '<code style="background:rgba(0,0,0,0.3);padding:2px 6px;border-radius:4px;">$1</code>');
            
            el.innerHTML += `
                <div class="message ${role}">
                    <div class="message-content markdown">${html}</div>
                    <div class="message-time">${time}</div>
                </div>
            `;
            
            if (scroll) el.scrollTop = el.scrollHeight;
        }
        
        function showTyping() {
            const el = document.getElementById('chat-area');
            el.innerHTML += `
                <div class="message assistant" id="typing-indicator">
                    <div class="typing"><span></span><span></span><span></span></div>
                </div>
            `;
            el.scrollTop = el.scrollHeight;
        }
        
        function hideTyping() {
            const el = document.getElementById('typing-indicator');
            if (el) el.remove();
        }
        
        async function sendMessage() {
            const input = document.getElementById('message-input');
            const message = input.value.trim();
            if (!message || isStreaming) return;
            
            input.value = '';
            addMessage('user', message);
            showTyping();
            
            isStreaming = true;
            document.getElementById('send-btn').disabled = true;
            
            try {
                const r = await fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message, session_id: sessionId })
                });
                const d = await r.json();
                
                hideTyping();
                addMessage('assistant', d.response);
                
                if (!sessionId) sessionId = d.session_id;
                loadSessions();
                loadInsights();
            } catch (e) {
                hideTyping();
                addMessage('assistant', 'Error: ' + e.message);
            }
            
            isStreaming = false;
            document.getElementById('send-btn').disabled = false;
        }
        
        function handleKeydown(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        }
        
        function quickAction(text) {
            document.getElementById('message-input').value = text;
            sendMessage();
        }
        
        // Auto-resize textarea
        document.getElementById('message-input').addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 120) + 'px';
        });
        
        // Initialize
        checkStatus();
        loadSessions();
        loadInsights();
        setInterval(checkStatus, 30000);
    </script>
</body>
</html>
"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
