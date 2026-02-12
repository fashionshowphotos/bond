"""
Bond Module: Firejumper Web Bridge
Exposes Firejumper's Web AI Automation as standard MCP tools.
Allows any MCP Client (Claude Desktop, etc.) to consult web models.
"""

import os
import json
import asyncio
import logging
import websockets
from core.module_loader import BondModule
from models.models import Tool, SafetyLevel

logger = logging.getLogger("bond.web_bridge")

class WebBridgeModule(BondModule):
    module_id = "web_bridge"

    # Config
    HUB_URL = os.environ.get("FIREJUMPER_HUB", "ws://localhost:7201")
    DEFAULT_TIMEOUT = 180 # 3 minutes for slow reasoning models

    def initialize(self, core):
        self.core = core

    def shutdown(self):
        pass

    def register_tools(self):
        return [
            Tool(
                name="ask_web_ai",
                description="Consult an external Web AI (ChatGPT, DeepSeek, Gemini, etc.) via the Firejumper Bridge. Use this when you need a second opinion, recent web info, or reasoning capability.",
                parameters={
                    "model": {
                        "type": "string",
                        "description": "Target AI ID: 'chatgpt', 'deepseek', 'claude', 'gemini', 'grok', 'kimi'",
                        "enum": ["chatgpt", "deepseek", "claude", "gemini", "grok", "kimi"]
                    },
                    "prompt": {
                        "type": "string",
                        "description": "The question or task for the external AI."
                    },
                    "force_new_chat": {
                        "type": "boolean",
                        "description": "If true, starts a fresh conversation context.",
                        "default": False,
                        "optional": True
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Optional session ID for conversation persistence. Each unique session_id gets its own ChatGPT window. Use this when multiple Claude instances need isolated conversations. Example: 'claude-1', 'claude-2', 'claude-3'",
                        "optional": True
                    }
                },
                handler=self.ask_ai,
                safety_level=SafetyLevel.MODERATE,  # Costs tokens/money or external calls
                module_id=self.module_id
            ),
            Tool(
                name="read_web_ai",
                description="Read the current screen/last response of a Web AI without sending a prompt.",
                parameters={
                    "model": {
                        "type": "string",
                        "description": "Target AI ID"
                    }
                },
                handler=self.read_ai,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id
            ),
            Tool(
                name="list_available_automations",
                description="List which Web AIs are currently active/ready in the Bridge.",
                parameters={},
                handler=self.list_ais,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id
            )
        ]

    # --- Handlers ---

    async def ask_ai(self, model: str, prompt: str, force_new_chat: bool = False, session_id: str = None):
        logger.debug("ask_ai: model=%s prompt_len=%d force_new_chat=%s session_id=%s",
                      model, len(prompt), force_new_chat, session_id)

        try:
            async with websockets.connect(self.HUB_URL) as ws:
                # Handshake via ping (hub validates type field on all messages)
                await ws.send(json.dumps({"type": "ping", "source": f"bond_mcp_{self.module_id}"}))

                req_id = f"mcp_ask_{int(asyncio.get_running_loop().time() * 1000)}"

                # Payload
                payload = {
                    "type": "ai_task",
                    "ai": model,
                    "prompt": prompt,
                    "reqId": req_id,
                    "newChat": force_new_chat
                }

                # MULTI-AGENT FIX: Add sessionId for conversation isolation
                if session_id:
                    logger.debug("Adding sessionId to payload: %s", session_id)
                    payload["sessionId"] = session_id

                await ws.send(json.dumps(payload))

                # Wait for response
                return await self._wait_for_response(ws, req_id)

        except Exception as e:
            logger.error("Failed to connect to Firejumper Hub: %s", e)
            return {"error": "Failed to connect to Firejumper Hub"}

    async def read_ai(self, model: str):
        # Use Hub's native scraping logic (which uses AI_PROFILES)
        try:
            async with websockets.connect(self.HUB_URL) as ws:
                await ws.send(json.dumps({"type": "ping", "source": f"bond_mcp_{self.module_id}"}))
                
                req_id = f"mcp_read_{int(asyncio.get_running_loop().time() * 1000)}"
                
                payload = {
                    "type": "get_last_response",
                    "ai": model,
                    "target": model, # Required for compatibility
                    "reqId": req_id
                }
                
                await ws.send(json.dumps(payload))
                
                # Wait for 'last_response' message
                response = await self._wait_for_response(ws, req_id)
                
                if response.get("success") or response.get("response"):
                    return {"last_message": response.get("response", "No content")}
                
                return {"error": response.get("error", "Unknown error reading AI")}
                
        except Exception as e:
            logger.error("read_ai connection failed: %s", e)
            return {"error": "Connection failed"}

    async def list_ais(self):
        # Query Firejumper hub for actually active windows
        try:
            async with websockets.connect(self.HUB_URL) as ws:
                await ws.send(json.dumps({"type": "ping", "source": f"bond_mcp_{self.module_id}"}))
                await ws.send(json.dumps({"type": "ai_list", "reqId": "list_ais"}))
                msg_raw = await asyncio.wait_for(ws.recv(), timeout=5.0)  # pong
                msg_raw = await asyncio.wait_for(ws.recv(), timeout=5.0)  # ai_list
                msg = json.loads(msg_raw)
                if msg.get("type") == "ai_list":
                    return msg.get("ais", [])
        except Exception:
            pass
        # Fallback to static list
        return ["chatgpt", "deepseek", "claude", "gemini", "grok"]

    # --- Helper ---
    
    async def _wait_for_response(self, ws, req_id):
        # Simple wait loop with timeout
        deadline = asyncio.get_running_loop().time() + self.DEFAULT_TIMEOUT
        
        while asyncio.get_running_loop().time() < deadline:
            try:
                msg_raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
                msg = json.loads(msg_raw)
                
                # Check match
                if msg.get("reqId") == req_id:
                    if msg.get("type") in ("ai_response", "browser_eval_result", "last_response"):
                        return msg
                    if msg.get("type") == "error":
                        return {"error": msg.get("error")}
                        
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("_wait_for_response error: %s", e)
                return {"error": "Communication error"}
                
        return {"error": "Timeout waiting for Web AI response"}
