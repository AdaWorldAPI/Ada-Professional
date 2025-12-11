"""
Ada Professional - Enterprise AI Assistant
Clean, business-focused, safe-for-work AI operations assistant
"""
import os
import json
import httpx
import hashlib
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="Ada Professional",
    description="Enterprise AI Assistant - Business Operations & Analysis",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Config - Separate Upstash for Professional instance
UPSTASH_URL = os.getenv("UPSTASH_REDIS_REST_URL", "")
UPSTASH_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")
JINA_KEY = os.getenv("JINA_API_KEY", "")


class Query(BaseModel):
    """User query."""
    text: str
    context: Optional[str] = None
    session_id: Optional[str] = None


class Memory(BaseModel):
    """Memory entry."""
    key: str
    content: str
    category: str = "general"
    

async def upstash_set(key: str, value: str, ex: int = 86400):
    """Store in Upstash Redis."""
    if not UPSTASH_URL:
        return False
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{UPSTASH_URL}/set/{key}",
            headers={"Authorization": f"Bearer {UPSTASH_TOKEN}"},
            json={"value": value, "ex": ex}
        )
        return resp.status_code == 200


async def upstash_get(key: str) -> Optional[str]:
    """Retrieve from Upstash Redis."""
    if not UPSTASH_URL:
        return None
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{UPSTASH_URL}/get/{key}",
            headers={"Authorization": f"Bearer {UPSTASH_TOKEN}"}
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("result")
        return None


async def upstash_keys(pattern: str) -> list:
    """Get keys matching pattern."""
    if not UPSTASH_URL:
        return []
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{UPSTASH_URL}/keys/{pattern}",
            headers={"Authorization": f"Bearer {UPSTASH_TOKEN}"}
        )
        if resp.status_code == 200:
            return resp.json().get("result", [])
        return []


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Ada Professional Dashboard."""
    return HTMLResponse("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Ada Professional</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #e4e8ec 100%);
            color: #333;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 800px; margin: 0 auto; }
        .header {
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 30px;
            padding: 24px;
            background: white;
            border-radius: 16px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.08);
        }
        .logo {
            width: 56px;
            height: 56px;
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
        }
        h1 { font-size: 24px; font-weight: 700; color: #1a1a2e; }
        .subtitle { color: #666; font-size: 14px; margin-top: 4px; }
        .card {
            background: white;
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.08);
        }
        .card h3 {
            color: #6366f1;
            margin-bottom: 16px;
            font-size: 16px;
            font-weight: 600;
        }
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 12px;
        }
        .status-item {
            background: #f8f9fa;
            padding: 16px;
            border-radius: 12px;
            text-align: center;
        }
        .status-value {
            font-size: 24px;
            font-weight: 700;
            color: #6366f1;
        }
        .status-label {
            font-size: 12px;
            color: #666;
            margin-top: 4px;
        }
        .chat-container {
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            overflow: hidden;
        }
        .chat-messages {
            height: 300px;
            overflow-y: auto;
            padding: 16px;
            background: #fafafa;
        }
        .message {
            margin-bottom: 12px;
            padding: 12px 16px;
            border-radius: 12px;
            max-width: 80%;
        }
        .message.user {
            background: #6366f1;
            color: white;
            margin-left: auto;
        }
        .message.ada {
            background: white;
            border: 1px solid #e5e7eb;
        }
        .chat-input {
            display: flex;
            padding: 16px;
            background: white;
            border-top: 1px solid #e5e7eb;
        }
        .chat-input input {
            flex: 1;
            padding: 12px 16px;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            font-size: 14px;
        }
        .chat-input button {
            background: #6366f1;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            margin-left: 8px;
            cursor: pointer;
            font-weight: 600;
        }
        .chat-input button:hover { background: #5558e3; }
        .capabilities {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 16px;
        }
        .capability {
            background: #f0f0ff;
            color: #6366f1;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🤖</div>
            <div>
                <h1>Ada Professional</h1>
                <div class="subtitle">Enterprise AI Assistant</div>
            </div>
        </div>

        <div class="card">
            <h3>System Status</h3>
            <div class="status-grid">
                <div class="status-item">
                    <div class="status-value" id="memory-count">-</div>
                    <div class="status-label">Memory Entries</div>
                </div>
                <div class="status-item">
                    <div class="status-value" id="uptime">✓</div>
                    <div class="status-label">Status</div>
                </div>
                <div class="status-item">
                    <div class="status-value">Pro</div>
                    <div class="status-label">Edition</div>
                </div>
            </div>
            <div class="capabilities">
                <span class="capability">📊 Data Analysis</span>
                <span class="capability">📝 Report Generation</span>
                <span class="capability">🔍 Research</span>
                <span class="capability">📈 Business Intelligence</span>
                <span class="capability">🛡️ Security Ops</span>
            </div>
        </div>

        <div class="card">
            <h3>Chat with Ada</h3>
            <div class="chat-container">
                <div class="chat-messages" id="chat-messages">
                    <div class="message ada">
                        Hello! I'm Ada Professional, your enterprise AI assistant. 
                        I can help with data analysis, report generation, research, 
                        and business operations. How can I assist you today?
                    </div>
                </div>
                <div class="chat-input">
                    <input type="text" id="chat-input" placeholder="Ask Ada anything..." 
                           onkeypress="if(event.key==='Enter')sendMessage()">
                    <button onclick="sendMessage()">Send</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function loadStatus() {
            try {
                const resp = await fetch('/api/status');
                const data = await resp.json();
                document.getElementById('memory-count').textContent = data.memory_count || '0';
            } catch (e) {
                console.error(e);
            }
        }

        async function sendMessage() {
            const input = document.getElementById('chat-input');
            const messages = document.getElementById('chat-messages');
            const text = input.value.trim();
            
            if (!text) return;
            
            // Add user message
            messages.innerHTML += `<div class="message user">${text}</div>`;
            input.value = '';
            messages.scrollTop = messages.scrollHeight;
            
            try {
                const resp = await fetch('/api/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({text: text})
                });
                const data = await resp.json();
                
                messages.innerHTML += `<div class="message ada">${data.response}</div>`;
                messages.scrollTop = messages.scrollHeight;
            } catch (e) {
                messages.innerHTML += `<div class="message ada">Sorry, I encountered an error. Please try again.</div>`;
            }
        }

        loadStatus();
    </script>
</body>
</html>""")


@app.get("/health")
async def health():
    """Health check."""
    return {
        "status": "healthy",
        "service": "Ada Professional",
        "edition": "enterprise",
        "upstash_connected": bool(UPSTASH_URL),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/status")
async def get_status():
    """Get system status."""
    memory_keys = await upstash_keys("ada:pro:*")
    return {
        "status": "operational",
        "memory_count": len(memory_keys),
        "upstash": bool(UPSTASH_URL)
    }


@app.post("/api/chat")
async def chat(query: Query):
    """Process chat query."""
    
    # Simple response logic (would integrate with Claude API in production)
    text = query.text.lower()
    
    # Store query in memory
    session_id = query.session_id or "default"
    query_hash = hashlib.md5(query.text.encode()).hexdigest()[:8]
    await upstash_set(
        f"ada:pro:query:{session_id}:{query_hash}",
        json.dumps({
            "text": query.text,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }),
        ex=86400 * 7  # 7 days
    )
    
    # Generate response based on query type
    if any(word in text for word in ["help", "can you", "what can"]):
        response = """I can assist you with:

• **Data Analysis** - Analyze datasets, find patterns, generate insights
• **Report Generation** - Create business reports, summaries, documentation  
• **Research** - Find information, compare options, compile research
• **Security Operations** - Monitor alerts, analyze threats, recommend actions
• **Business Intelligence** - KPIs, metrics, dashboards, forecasting

What would you like to work on?"""

    elif any(word in text for word in ["security", "threat", "alert"]):
        response = """For security operations, I integrate with GraphSentinel for:

• Real-time threat monitoring
• Automated alert analysis
• Remediation recommendations
• Voice alerts to your team

Would you like me to check the current security status or configure alerts?"""

    elif any(word in text for word in ["report", "summary", "document"]):
        response = """I can help create reports. Please tell me:

1. What type of report? (status, analysis, executive summary)
2. What data or topic should it cover?
3. Who is the audience?

Share these details and I'll draft a professional report for you."""

    elif any(word in text for word in ["analyze", "data", "metrics"]):
        response = """Ready to analyze your data. You can:

• Share a dataset or metrics
• Ask about specific KPIs
• Request trend analysis
• Compare performance periods

What data would you like me to look at?"""

    else:
        response = f"""I understand you're asking about: "{query.text}"

As your professional AI assistant, I'm here to help with business operations, analysis, and productivity. Could you provide more context about what you'd like to accomplish?

For example:
- "Analyze last quarter's sales data"
- "Create a security status report"
- "Research competitors in [market]"
- "Summarize this document" """

    return {
        "response": response,
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/memory")
async def store_memory(memory: Memory):
    """Store memory entry."""
    key = f"ada:pro:mem:{memory.category}:{memory.key}"
    await upstash_set(key, memory.content, ex=86400 * 30)  # 30 days
    return {"status": "stored", "key": key}


@app.get("/api/memory/{category}")
async def get_memories(category: str):
    """Retrieve memories by category."""
    keys = await upstash_keys(f"ada:pro:mem:{category}:*")
    memories = []
    for key in keys[:50]:  # Limit to 50
        value = await upstash_get(key)
        if value:
            memories.append({"key": key, "content": value})
    return {"category": category, "memories": memories}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
