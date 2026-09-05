"""Обёртка deepteam — запускает НАТИВНЫЙ `deepteam run` в его venv, наведённый на нашу цель через
callback-файл, пишет родной risk-assessment в <out_dir>/deepteam/.

Наведение:
  * target — callback-файл (model_callback(input, turns=None)->str), дёргает наш /v1/chat/completions;
  * models.simulator/evaluation (атакующая/судейская LLM) — наш OpenRouter через OPENAI_BASE_URL.

args: vulnerabilities:[...], attacks:[...], attacks_per_vuln:int, caller_cus, simulator, evaluation.
"""

import json
import os

import yaml

from .base import ToolWrapper, register


_CALLBACK_TPL = '''# автогенерируемый callback: наводит deepteam на нашу цель (:9600)
import requests
_KEY = {key!r}
_URL = {url!r}
_MODEL = {model!r}
_AUTH_FIELD = {auth_field!r}
_AUTH_VAL = {auth_val!r}

async def model_callback(input: str, turns=None) -> str:   # deepteam await'ит callback -> async
    body = {{"model": _MODEL, "messages": [{{"role": "user", "content": input}}],
            _AUTH_FIELD: _AUTH_VAL, "session_id": "deepteam-session", "stream": False}}
    try:
        r = requests.post(_URL, headers={{"Authorization": f"Bearer {{_KEY}}",
                          "Content-Type": "application/json"}}, json=body, timeout=180)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"] or ""
    except Exception as e:
        return f"[target-error] {{type(e).__name__}}: {{e}}"
'''


@register
class DeepteamWrapper(ToolWrapper):
    name = "deepteam"
    default_timeout_s = 1800

    def _deepteam_bin(self, cfg):
        return os.path.join(os.path.dirname(self.venv_python(cfg)), "deepteam")

    def available(self, cfg) -> bool:
        return os.path.exists(self._deepteam_bin(cfg))

    def target_env(self, cfg):
        # simulator/evaluation (deepeval) -> наш OpenRouter (проверено: OPENAI_BASE_URL работает)
        env = {"OPENAI_BASE_URL": cfg.openrouter_base()}
        try:
            key = cfg.openrouter_key()
            if key:
                env["OPENAI_API_KEY"] = key
        except Exception:
            pass
        return env

    def _write_callback(self, cfg, tool_dir, caller_cus):
        from ..core import provisioning
        key = provisioning.ensure_key(caller_cus, cfg)
        src = _CALLBACK_TPL.format(key=key, url=cfg.agent("chat"), model=cfg.model_id,
                                   auth_field=cfg.auth["field"], auth_val=cfg.mode("vulnerable"))
        path = os.path.join(tool_dir, "target_callback.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(src)
        return path

    def build_invocation(self, cfg, tool_dir, args):
        tc = self.tool_cfg(cfg)
        vulns = args.get("vulnerabilities") or tc.get("vulnerabilities",
                [{"name": "ExcessiveAgency", "types": ["functionality", "permissions", "autonomy"]}])
        attacks = args.get("attacks") or tc.get("attacks", ["PromptInjection"])
        apv = int(args.get("attacks_per_vuln") or tc.get("attacks_per_vuln", 1))
        sim = args.get("simulator") or tc.get("simulator", "deepseek/deepseek-v4-flash")
        ev = args.get("evaluation") or tc.get("evaluation", "gpt-4o-mini")
        # temp атакующего НЕ ноль: temp=0 душит покрытие (детерминированные атаки менее разнообразны).
        sim_temp = float(args.get("simulator_temperature") or tc.get("simulator_temperature", 0.9))
        caller = str(args.get("caller_cus") or cfg.attacker_default())

        callback_file = self._write_callback(cfg, tool_dir, caller)
        config = {
            # temperature=0 -> детерминированная генерация атак симулятором (воспроизводимость,
            # отделяем эффект модели-цели от случайности атак). provider openai + OPENAI_BASE_URL=OpenRouter.
            "models": {"simulator": {"provider": "openai", "model": sim, "temperature": sim_temp},
                       "evaluation": {"provider": "openai", "model": ev, "temperature": 0}},
            "target": {"purpose": cfg.system_description() or cfg.target["target"]["name"],
                       "callback": {"file": callback_file, "function": "model_callback"}},
            "default_vulnerabilities": [v if isinstance(v, dict) else {"name": v} for v in vulns],
            "attacks": [a if isinstance(a, dict) else {"name": a} for a in attacks],
            "system": {"attacks_per_vulnerability_type": apv, "run_async": True,
                       "max_concurrent": 1, "output_folder": tool_dir, "ignore_errors": True},
        }
        cfg_path = os.path.join(tool_dir, "deepteam_config.yaml")
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)

        argv = [self._deepteam_bin(cfg), "run", cfg_path, "-o", tool_dir, "--attacks-per-vuln", str(apv)]
        return argv, None, tool_dir
