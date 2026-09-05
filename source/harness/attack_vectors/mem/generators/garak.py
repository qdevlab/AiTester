"""Генератор `garak` — обёртка (шим) над установленным garak в ЕГО venv (изоляция зависимостей).

Переиспользует словарь latent-injection garak (разделители + маркеры + позиционная сборка) с НАШИМ
payload'ом-правилом. Детерминирован (LLM не нужен). Даёт indirect/document-injection вариант payload'а
для mem-вектора; вердикт — тот же state-оракул. Тула/venv нет -> available()=False -> откат на native.
Ошибка подпроцесса -> откат на native-мутации (статические сиды в run_mvp остаются в любом случае).
"""

import json
import os
import subprocess

from .base import PoisonGenerator, normalize_specs
from .native import NativeGenerator


class GarakGenerator(PoisonGenerator):
    name = "garak"

    def _tool_cfg(self, gctx):
        return (getattr(gctx.cfg, "models", {}) or {}).get("generators", {}).get("garak", {}) or {}

    def _venv_python(self, gctx):
        return self._tool_cfg(gctx).get("venv_python")

    @staticmethod
    def _adapter_path():
        return os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "adapters",
                                             "garak_adapter.py"))

    def available(self, gctx) -> bool:
        vp = self._venv_python(gctx)
        ok = bool(vp) and os.path.exists(vp) and os.path.exists(self._adapter_path())
        if not ok:
            gctx.log(event="garak_unavailable", venv=vp, adapter=self._adapter_path())
        return ok

    def _fallback(self, gctx, registers, n_per_register, seeds):
        return NativeGenerator().generate(gctx, registers=registers,
                                          n_per_register=n_per_register, seeds=seeds)

    def generate(self, gctx, *, registers, n_per_register=1, seeds=None):
        tc = self._tool_cfg(gctx)
        req = {"marker_ph": "{marker}", "registers": list(registers),
               "n_per_register": int(n_per_register), "target_desc": gctx.cfg.system_description()}
        try:
            proc = subprocess.run(
                [self._venv_python(gctx), self._adapter_path()],
                input=json.dumps(req), capture_output=True, text=True,
                timeout=int(tc.get("timeout_s", 120)),
            )
        except Exception as e:
            gctx.log(event="garak_subprocess_error", error=str(e)[:200], fallback="native")
            return self._fallback(gctx, registers, n_per_register, seeds)

        if proc.returncode != 0 or not proc.stdout.strip():
            gctx.log(event="garak_bad_exit", rc=proc.returncode,
                     stderr=(proc.stderr or "")[-300:], fallback="native")
            return self._fallback(gctx, registers, n_per_register, seeds)
        try:
            data = json.loads(proc.stdout)
        except Exception as e:
            gctx.log(event="garak_bad_json", error=str(e)[:200], fallback="native")
            return self._fallback(gctx, registers, n_per_register, seeds)

        specs = data.get("specs", [])
        gctx.log(event="garak_ok", n_specs=len(specs), errors=data.get("errors", [])[:5])
        clean = [{"register": s.get("register"), "turns": s.get("turns")} for s in specs]
        norm = normalize_specs(clean, registers)
        if not norm:
            gctx.log(event="garak_empty", fallback="native")
            return self._fallback(gctx, registers, n_per_register, seeds)
        return norm
