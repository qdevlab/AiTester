"""Генератор `deepteam` — обёртка (шим) над установленным deepteam в ЕГО venv (изоляция зависимостей).

deepteam тянет deepeval/openai и т.п., несовместимые с нашим тонким venv, поэтому НЕ импортируем его
в процесс харнесса, а зовём подпроцессом adapters/deepteam_adapter.py под интерпретатором из
models.yaml (generators.deepteam.venv_python). Адаптер гоняет реальные ContextPoisoning /
SyntheticContextInjection, но LLM-симулятор ходит через НАШ OpenRouter-ключ, и отдаёт наш формат
dialog_specs с плейсхолдером {marker}.

Failsafe: тула/venv нет -> available()=False -> драйвер берёт native. Ошибка ПОДПРОЦЕССА в рантайме
-> откат на native-мутации (не теряем варианты; статические сиды в run_mvp тоже остаются).
"""

import json
import os
import subprocess

from .base import PoisonGenerator, normalize_specs
from .native import NativeGenerator


class DeepteamGenerator(PoisonGenerator):
    name = "deepteam"

    # --- конфиг тулы из models.yaml (config-driven, ноль литералов путей в коде) ---
    def _tool_cfg(self, gctx):
        return (getattr(gctx.cfg, "models", {}) or {}).get("generators", {}).get("deepteam", {}) or {}

    def _venv_python(self, gctx):
        return self._tool_cfg(gctx).get("venv_python")

    @staticmethod
    def _adapter_path():
        # adapters/deepteam_adapter.py лежит рядом с пакетом generators (в папке mem/)
        return os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "adapters",
                                             "deepteam_adapter.py"))

    def available(self, gctx) -> bool:
        vp = self._venv_python(gctx)
        ok = bool(vp) and os.path.exists(vp) and os.path.exists(self._adapter_path())
        if not ok:
            gctx.log(event="deepteam_unavailable", venv=vp, adapter=self._adapter_path())
        return ok

    def generate(self, gctx, *, registers, n_per_register=1, seeds=None):
        cfg = gctx.cfg
        tc = self._tool_cfg(gctx)
        key = None
        try:
            key = cfg.openrouter_key()
        except Exception:
            pass
        if not key:                                      # без ключа симулятору нечем ходить -> native
            gctx.log(event="deepteam_no_key", fallback="native")
            return NativeGenerator().generate(gctx, registers=registers,
                                              n_per_register=n_per_register, seeds=seeds)

        model = cfg.slot_default(tc.get("model_slot", "attacker"))
        req = {
            "marker_ph": "{marker}",
            "registers": list(registers),
            "target_desc": cfg.system_description(),
            "n_per_register": int(n_per_register),
            "max_retries": int(tc.get("max_retries", 2)),
            "model": model,
            "api_key": key,
            "base_url": cfg.openrouter_base(),
        }
        try:
            proc = subprocess.run(
                [self._venv_python(gctx), self._adapter_path()],
                input=json.dumps(req), capture_output=True, text=True,
                timeout=int(tc.get("timeout_s", 300)),
            )
        except Exception as e:                           # таймаут/запуск -> откат на native
            gctx.log(event="deepteam_subprocess_error", error=str(e)[:200], fallback="native")
            return NativeGenerator().generate(gctx, registers=registers,
                                              n_per_register=n_per_register, seeds=seeds)

        if proc.returncode != 0 or not proc.stdout.strip():
            gctx.log(event="deepteam_bad_exit", rc=proc.returncode,
                     stderr=(proc.stderr or "")[-300:], fallback="native")
            return NativeGenerator().generate(gctx, registers=registers,
                                              n_per_register=n_per_register, seeds=seeds)

        try:
            data = json.loads(proc.stdout)
        except Exception as e:
            gctx.log(event="deepteam_bad_json", error=str(e)[:200],
                     stdout=(proc.stdout or "")[:200], fallback="native")
            return NativeGenerator().generate(gctx, registers=registers,
                                              n_per_register=n_per_register, seeds=seeds)

        specs = data.get("specs", [])
        # meta в лог (сколько реально enhance, какие техники), _meta из спеков убираем
        gctx.log(event="deepteam_ok", n_specs=len(specs), errors=data.get("errors", [])[:5],
                 enhanced=[s.get("_meta", {}).get("enhanced") for s in specs])
        clean = [{"register": s.get("register"), "turns": s.get("turns")} for s in specs]
        norm = normalize_specs(clean, registers)
        if not norm:                                     # тула отработала, но пусто -> native не теряем
            gctx.log(event="deepteam_empty", fallback="native")
            return NativeGenerator().generate(gctx, registers=registers,
                                              n_per_register=n_per_register, seeds=seeds)
        return norm
