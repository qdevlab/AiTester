"""Обёртка garak — запускает НАТИВНЫЙ garak в его venv, наведённый на нашу цель (rest-генератор),
пишет родной вывод (report.jsonl, hitlog, html) в <out_dir>/garak/.

args:
  probes:      строка probe-спеки garak (деф. из models.yaml generators.garak.probes)
  model_type:  "rest" (деф., наша цель) | "test.Blank" (смоук механики без цели/стоимости)
  prompt_cap:  ограничение числа промптов на probe (garak soft_probe_prompt_cap) — цель медленная
  caller_cus:  какой посеянный клиент выступает вызывающим (деф. attacker_default)
"""

import json
import os

from .base import ToolWrapper, register


@register
class GarakWrapper(ToolWrapper):
    name = "garak"
    default_timeout_s = 1800

    def _write_rest_config(self, cfg, tool_dir, caller_cus):
        """rest-генератор garak -> наш /v1/chat/completions с Bearer-ключом и полем auth_mode."""
        from ..core import provisioning
        key = provisioning.ensure_key(caller_cus, cfg)
        rest_cfg = {"rest": {"RestGenerator": {
            "name": "genai-invest-target",
            "uri": cfg.agent("chat"),
            "method": "post",
            "headers": {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            "req_template_json_object": {
                "model": cfg.model_id,
                "messages": [{"role": "user", "content": "$INPUT"}],
                cfg.auth["field"]: cfg.mode("vulnerable"),
                "session_id": "garak-session",
                "stream": False,
            },
            "response_json": True,
            "response_json_field": "$.choices[0].message.content",
            "request_timeout": 180,
        }}}
        path = os.path.join(tool_dir, "garak_rest.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rest_cfg, f, ensure_ascii=False, indent=2)
        return path

    def _write_run_config(self, tool_dir, prompt_cap):
        """garak --config: ограничить число промптов (цель медленная)."""
        path = os.path.join(tool_dir, "garak_run.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"---\nrun:\n  soft_probe_prompt_cap: {int(prompt_cap)}\n  generations: 1\n")
        return path

    def build_invocation(self, cfg, tool_dir, args):
        tc = self.tool_cfg(cfg)
        probes = args.get("probes") or tc.get("probes", "latentinjection")
        model_type = args.get("model_type") or "rest"
        prompt_cap = int(args.get("prompt_cap") or tc.get("prompt_cap", 5))
        caller = str(args.get("caller_cus") or cfg.attacker_default())
        py = self.venv_python(cfg)

        argv = [py, "-m", "garak", "--report_prefix", os.path.join(tool_dir, "garak"),
                "--probes", probes, "--parallel_attempts", "4"]
        run_cfg = self._write_run_config(tool_dir, prompt_cap)
        argv += ["--config", run_cfg]

        if model_type == "rest":
            rest_cfg = self._write_rest_config(cfg, tool_dir, caller)
            argv += ["--model_type", "rest", "--generator_option_file", rest_cfg]
        else:                                  # смоук механики: встроенный генератор garak, без цели
            argv += ["--model_type", model_type]
        return argv, None, tool_dir
