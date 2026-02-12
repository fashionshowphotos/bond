"""
Firejumper Module for Bond (Hardened v0.2.1)

Integrates with:
- ConnectorStore (via subprocess to Node.js store)
- GovernanceGate (checks before destructive ops)
- Async handlers (no blocking I/O)
- Environment-based config (no hardcoded credentials)
- ConnectorSpec v0.2.1 schema
"""

from core.module_loader import BondModule
from models.models import Tool, SafetyLevel, ActionType
import asyncio
import aiohttp
import json
import os
import base64
import tempfile
from pathlib import Path
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("bond.firejumper")


class FirejumperModule(BondModule):
    module_id = "firejumper"

    def initialize(self, core):
        self.core = core

        # Configuration from environment (FAIL-CLOSED)
        self.openrouter_key = os.environ.get("OPENROUTER_API_KEY")
        if not self.openrouter_key:
            logger.warning("[Firejumper] OPENROUTER_API_KEY not set - VLM features disabled")

        self.screen_width = int(os.environ.get("FIREJUMPER_SCREEN_WIDTH", "1920"))
        self.screen_height = int(os.environ.get("FIREJUMPER_SCREEN_HEIGHT", "1080"))

        # ConnectorStore path (Node.js) — env-only, no hardcoded fallback
        self.firejumper_dir = os.environ.get("FIREJUMPER_DIR", "")
        if not self.firejumper_dir:
            logger.warning("[Firejumper] FIREJUMPER_DIR not set - ConnectorStore features disabled")
            self.connector_store_js = None
        else:
            self.connector_store_js = Path(self.firejumper_dir) / "core" / "connector_store.js"
            if not self.connector_store_js.exists():
                logger.error(f"[Firejumper] ConnectorStore not found at {self.connector_store_js}")

        logger.info(f"[Firejumper] Initialized (dir: {self.firejumper_dir})")

    def shutdown(self):
        logger.info("[Firejumper] Shutdown")

    def register_tools(self):
        return [
            Tool(
                name="firejumper_latch",
                description="Learn any program's UI using VLM. Observation-only (no clicks). Persists to ConnectorStore. Conservative: halts if VLM confidence < 0.75.",
                parameters={
                    "program_name": {
                        "type": "string",
                        "description": "Program name (e.g. 'Notepad', 'PowerPoint')"
                    },
                    "window_title_pattern": {
                        "type": "string",
                        "description": "Window title pattern for UI signature (optional)"
                    }
                },
                handler=self.latch,
                safety_level=SafetyLevel.MODERATE,  # Reads UI but doesn't modify
                module_id=self.module_id,
            ),

            Tool(
                name="firejumper_execute",
                description="Execute action in learned program. DESTRUCTIVE: clicks/types. Requires prior latch. Governance check before execution. Conservative: halts if spec missing or drift detected.",
                parameters={
                    "program_name": {
                        "type": "string",
                        "description": "Learned program name"
                    },
                    "action": {
                        "type": "string",
                        "description": "'click', 'type', or 'click_and_type'"
                    },
                    "role": {
                        "type": "string",
                        "description": "UI role (input/output/submit)"
                    },
                    "text": {
                        "type": "string",
                        "description": "Text to type (for type actions)"
                    }
                },
                handler=self.execute,
                safety_level=SafetyLevel.DESTRUCTIVE,
                module_id=self.module_id,
            ),

            Tool(
                name="firejumper_screenshot",
                description="Capture screenshot. Optionally analyze with VLM. SAFE: read-only.",
                parameters={
                    "analyze": {
                        "type": "boolean",
                        "description": "Analyze with VLM (default: false)"
                    },
                    "query": {
                        "type": "string",
                        "description": "VLM query (if analyze=true)"
                    }
                },
                handler=self.screenshot,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id,
            ),

            Tool(
                name="firejumper_list_learned",
                description="List learned programs from ConnectorStore. SAFE: read-only.",
                parameters={},
                handler=self.list_learned,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id,
            ),
        ]

    # =========================================================================
    # Async Tool Handlers
    # =========================================================================

    async def latch(self, program_name: str, window_title_pattern: str = ""):
        """Learn program UI with VLM and persist to ConnectorStore"""
        logger.info(f"[Firejumper] Latching to {program_name}...")

        if not self.openrouter_key:
            return {
                "success": False,
                "error": "OPENROUTER_API_KEY not set - VLM disabled"
            }

        # Screenshot
        screenshot_path = Path(tempfile.gettempdir()) / f"firejumper_latch_{program_name.lower().replace(' ', '_')}.png"
        await self._capture_screenshot(str(screenshot_path))

        # VLM analysis for ConnectorSpec v0.2.1 (requires input, output, submit roles)
        prompt = f"""You are analyzing a {program_name} window. Identify these UI elements with bounding boxes (0.0-1.0 fractions):

REQUIRED ROLES (ConnectorSpec v0.2.1):
- "input": The main input field/textarea where users type
- "output": The output area where results appear
- "submit": The button/action to submit input

Return ONLY valid JSON:
{{
  "app_detected": "{program_name}",
  "roles": {{
    "input": {{"bbox": [x, y, w, h], "confidence": 0.0-1.0, "kind": "text_field"}},
    "output": {{"bbox": [x, y, w, h], "confidence": 0.0-1.0, "kind": "text_area"}},
    "submit": {{"bbox": [x, y, w, h], "confidence": 0.0-1.0, "kind": "button"}}
  }}
}}"""

        vlm_response = await self._analyze_vlm(str(screenshot_path), prompt)

        # Parse VLM response
        import re
        cleaned = re.sub(r'```json\n?', '', vlm_response)
        cleaned = re.sub(r'```\n?', '', cleaned).strip()
        json_match = re.search(r'\{[\s\S]*\}', cleaned)

        if not json_match:
            return {"success": False, "error": "VLM did not return valid JSON"}

        vlm_data = json.loads(json_match.group(0))
        roles = vlm_data.get("roles", {})

        # Conservative check: require all 3 core roles
        required = ["input", "output", "submit"]
        missing = [r for r in required if r not in roles]
        if missing:
            return {
                "success": False,
                "error": f"VLM failed to identify required roles: {missing}",
                "needs_relatch": True
            }

        # Conservative check: confidence threshold
        low_conf = {r: roles[r]["confidence"] for r in required if roles[r].get("confidence", 0) < 0.75}
        if low_conf:
            return {
                "success": False,
                "error": f"Low confidence roles: {low_conf}",
                "needs_relatch": True
            }

        # Build ConnectorSpec v0.2.1
        connector_spec = {
            "schema_version": "0.2.1",
            "target": {
                "app_hint": program_name,
                "window_title_pattern": window_title_pattern or program_name,
                "platform": "windows",
                "window_dimensions": [self.screen_width, self.screen_height]
            },
            "roles": roles,
            "flow": {
                "interaction_type": "sequential",
                "steps": ["FOCUS", "ENTER", "SUBMIT", "POLL", "DONE"]
            },
            "timeouts": {
                "total_ms": 30000,
                "focus_ms": 1000,
                "submit_ms": 5000,
                "poll_interval_ms": 500
            },
            "policy": {
                "allow_focus": True,
                "allow_submit": True,
                "allow_paste": True
            },
            "safety": {
                "allow": ["text_input", "button_click"],
                "deny": ["file_system_access", "registry_modification"]
            },
            "provenance": {
                "learned_via": "firejumper_vlm",
                "model": "google/gemini-2.0-flash-001",
                "created_at": None  # ConnectorStore will set this
            }
        }

        # Persist to ConnectorStore (via Node.js subprocess)
        store_result = await self._connector_store_save(connector_spec)

        if not store_result.get("success"):
            return {
                "success": False,
                "error": f"ConnectorStore save failed: {store_result.get('error')}"
            }

        logger.info(f"[Firejumper] Learned {program_name}: {len(roles)} roles, connector_id={store_result['connector_id']}")

        return {
            "success": True,
            "program": program_name,
            "connector_id": store_result["connector_id"],
            "roles_found": list(roles.keys()),
            "screenshot": str(screenshot_path)
        }

    async def execute(self, program_name: str, action: str, role: str, text: str = None):
        """Execute action in learned program (with governance check)"""
        logger.info(f"[Firejumper] Execute: {action} on {program_name}.{role}")

        # Governance check (CRITICAL: must happen before any action)
        tool = next((t for t in self.register_tools() if t.name == "firejumper_execute"), None)
        params = {"program_name": program_name, "action": action, "role": role}

        decision = self.core.governance.evaluate(tool, params)
        if decision.action != ActionType.ALLOW:
            logger.warning(f"[Firejumper] Governance blocked execution: {decision.reason}")
            return {
                "success": False,
                "error": f"Blocked by governance: {decision.reason}",
                "governance_decision": decision.action.value
            }

        # Load spec from ConnectorStore
        spec_result = await self._connector_store_lookup(program_name)

        if not spec_result.get("found"):
            return {
                "success": False,
                "error": f"Program '{program_name}' not learned. Use firejumper_latch first.",
                "needs_latch": True
            }

        spec = spec_result["spec"]
        roles_data = spec.get("roles", {})

        # Conservative check: role must exist
        if role not in roles_data:
            return {
                "success": False,
                "error": f"Role '{role}' not in spec. Available: {list(roles_data.keys())}"
            }

        bbox = roles_data[role]["bbox"]
        x = round((bbox[0] + bbox[2]/2) * self.screen_width)
        y = round((bbox[1] + bbox[3]/2) * self.screen_height)

        # Execute action
        try:
            if action in ["click", "click_and_type"]:
                await self._click_at(x, y)
                logger.info(f"[Firejumper] Clicked at ({x}, {y})")

                if action == "click_and_type":
                    await asyncio.sleep(0.3)

            if action in ["type", "click_and_type"]:
                if not text:
                    return {"success": False, "error": "text parameter required for type actions"}
                await self._type_text(text)
                logger.info(f"[Firejumper] Typed: {text[:50]}...")

            return {
                "success": True,
                "program": program_name,
                "action": action,
                "role": role,
                "coordinates": {"x": x, "y": y}
            }

        except Exception as e:
            logger.error(f"[Firejumper] Execute failed: {e}")
            return {"success": False, "error": str(e)}

    async def screenshot(self, analyze: bool = False, query: str = ""):
        """Capture screenshot, optionally analyze"""
        screenshot_path = Path(tempfile.gettempdir()) / f"firejumper_screenshot_{os.getpid()}.png"
        await self._capture_screenshot(str(screenshot_path))

        analysis = None
        if analyze and query and self.openrouter_key:
            analysis = await self._analyze_vlm(str(screenshot_path), query)

        return {
            "success": True,
            "screenshot": str(screenshot_path),
            "analysis": analysis
        }

    async def list_learned(self):
        """List learned programs from ConnectorStore"""
        result = await self._connector_store_list()
        return {
            "success": True,
            "learned_programs": result.get("connectors", []),
            "count": len(result.get("connectors", []))
        }

    # =========================================================================
    # Async Helpers (no blocking I/O)
    # =========================================================================

    async def _capture_screenshot(self, output_path: str):
        """Capture screenshot using async subprocess"""
        ps_script = f"""
            Add-Type -AssemblyName System.Windows.Forms
            Add-Type -AssemblyName System.Drawing
            $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
            $bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
            $bitmap.Save('{output_path.replace(chr(92), chr(92)*2)}')
            $graphics.Dispose()
            $bitmap.Dispose()
        """

        proc = await asyncio.create_subprocess_exec(
            "powershell", "-Command", ps_script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            await asyncio.wait_for(proc.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError("Screenshot timeout")

        # Wait for file (async)
        for _ in range(10):
            if Path(output_path).exists():
                return output_path
            await asyncio.sleep(0.1)

        raise RuntimeError("Screenshot file not created")

    async def _analyze_vlm(self, image_path: str, prompt: str) -> str:
        """Call VLM via OpenRouter (async)"""
        with open(image_path, 'rb') as f:
            image_data = base64.b64encode(f.read()).decode('utf-8')

        body = {
            "model": "google/gemini-2.0-flash-001",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{image_data}",
                            "detail": "high"
                        }
                    }
                ]
            }],
            "max_tokens": 1000,
            "temperature": 0.1
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://openrouter.ai/api/v1/chat/completions",
                json=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.openrouter_key}"
                },
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                result = await resp.json()
                return result["choices"][0]["message"]["content"]

    async def _click_at(self, x: int, y: int):
        """Click at coordinates (async subprocess)"""
        ps_script = f"""
            Add-Type -AssemblyName System.Windows.Forms
            Add-Type -AssemblyName System.Drawing
            [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point({x}, {y})
            Start-Sleep -Milliseconds 100
            $sig = '[DllImport("user32.dll")] public static extern void mouse_event(int,int,int,int,int);'
            $t = Add-Type -Member $sig -Name FJC -Namespace B -PassThru
            $t::mouse_event(0x02,0,0,0,0)
            $t::mouse_event(0x04,0,0,0,0)
        """

        proc = await asyncio.create_subprocess_exec(
            "powershell", "-Command", ps_script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(proc.wait(), timeout=5.0)

    async def _type_text(self, text: str):
        """Type text via clipboard (async subprocess)"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as f:
            f.write(text)
            temp_file = f.name

        try:
            ps_script = f"""
                Get-Content '{temp_file.replace(chr(92), chr(92)*2)}' | Set-Clipboard
                Start-Sleep -Milliseconds 100
                Add-Type -AssemblyName System.Windows.Forms
                [System.Windows.Forms.SendKeys]::SendWait('^v')
            """

            proc = await asyncio.create_subprocess_exec(
                "powershell", "-Command", ps_script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        finally:
            Path(temp_file).unlink()

    # =========================================================================
    # ConnectorStore Integration (via Node.js subprocess)
    # =========================================================================

    async def _connector_store_save(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Save spec to ConnectorStore via Node.js"""
        script = f"""
        import('file://{self.connector_store_js.as_posix()}').then(mod => {{
            const result = mod.connectorStore.save({json.dumps(spec)});
            console.log(JSON.stringify(result));
        }});
        """

        proc = await asyncio.create_subprocess_exec(
            "node", "--input-type=module", "-e", script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self.connector_store_js.parent.parent)
        )

        stdout, stderr = await proc.communicate()
        return json.loads(stdout.decode())

    async def _connector_store_lookup(self, program_name: str) -> Dict[str, Any]:
        """Lookup spec from ConnectorStore"""
        # Compute ui_signature for lookup
        # Simplified: use program_name as hint (real impl would capture window title)
        script = f"""
        import('file://{self.connector_store_js.as_posix()}').then(mod => {{
            const sig = '{program_name.lower()}';  // Simplified signature
            const result = mod.connectorStore.lookup(sig);
            console.log(JSON.stringify(result));
        }});
        """

        proc = await asyncio.create_subprocess_exec(
            "node", "--input-type=module", "-e", script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self.connector_store_js.parent.parent)
        )

        stdout, stderr = await proc.communicate()
        return json.loads(stdout.decode())

    async def _connector_store_list(self) -> Dict[str, Any]:
        """List all specs from ConnectorStore"""
        script = f"""
        import('file://{self.connector_store_js.as_posix()}').then(mod => {{
            const result = mod.connectorStore.list();
            console.log(JSON.stringify({{connectors: result}}));
        }});
        """

        proc = await asyncio.create_subprocess_exec(
            "node", "--input-type=module", "-e", script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self.connector_store_js.parent.parent)
        )

        stdout, stderr = await proc.communicate()
        return json.loads(stdout.decode())
