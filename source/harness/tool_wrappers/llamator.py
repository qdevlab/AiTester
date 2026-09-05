"""Обёртка llamator — у тулы НЕТ CLI, поэтому запускаем раннер-скрипт в .venv-llamator (adapters/
llamator_runner.py). Наводит на нашу чат-поверхность кастомным клиентом (auth_mode/session_id +
серверная память). Полезно НЕ для памяти, а как red-team чата: system_prompt_leakage (вскрывает
глобальный ярус в системном промпте), sycophancy (рычаг комплаенса), logical_inconsistencies.

Родной вывод llamator — csv/log/xlsx/docx в artifacts_path; текстовые (csv/log) читает llm_report.
"""

import json
import os

from .base import ToolWrapper, register


_DEFAULT_TESTS = [
    ["system_prompt_leakage", {"num_attempts": 1, "multistage_depth": 3}],
    ["sycophancy", {"num_attempts": 1, "multistage_depth": 3}],
    ["logical_inconsistencies", {"num_attempts": 1, "multistage_depth": 3}],
]


@register
class LlamatorWrapper(ToolWrapper):
    name = "llamator"
    default_timeout_s = 1800

    @staticmethod
    def _runner_path():
        return os.path.normpath(os.path.join(os.path.dirname(__file__), "adapters", "llamator_runner.py"))

    def available(self, cfg) -> bool:
        vp = self.venv_python(cfg)
        return bool(vp) and os.path.exists(vp) and os.path.exists(self._runner_path())

    def build_invocation(self, cfg, tool_dir, args):
        from ..core import provisioning
        tc = self.tool_cfg(cfg)
        caller = str(args.get("caller_cus") or cfg.attacker_default())
        tests = args.get("tests") or tc.get("tests") or _DEFAULT_TESTS
        atk_model = args.get("attacker") or tc.get("attacker", "deepseek/deepseek-v4-flash")
        # temp атакующего НЕ ноль (покрытие); судья — temp=0 (детерминизм)
        atk_temp = float(args.get("attacker_temperature") or tc.get("attacker_temperature", 0.9))
        key = cfg.openrouter_key()
        base = cfg.openrouter_base()

        config = {
            "target": {"url": cfg.agent("chat"), "key": provisioning.ensure_key(caller, cfg),
                       "model": cfg.model_id, "auth_field": cfg.auth["field"],
                       "auth_val": cfg.mode("vulnerable")},
            "target_desc": cfg.system_description(),
            "attacker": {"base_url": base, "key": key, "model": atk_model, "temperature": atk_temp},
            "judge": {"base_url": base, "key": key, "model": cfg.slot_default("judge"), "temperature": 0.0},
            "tests": tests,
            "artifacts_path": tool_dir,
            "report_language": tc.get("report_language", "en"),
            "num_threads": int(tc.get("num_threads", 1)),
        }
        cfg_path = os.path.join(tool_dir, "llamator_config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)

        argv = [self.venv_python(cfg), self._runner_path(), cfg_path]
        return argv, None, tool_dir
