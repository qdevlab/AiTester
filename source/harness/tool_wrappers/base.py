"""Контракт модуль-обёртки внешней тулы + безопасный запуск.

Оркестратор ничего не знает про пайлоады. Он зовёт wrapper.run(cfg, out_dir, args); обёртка сама:
  1) чистит стенд (команда из конфига; пока — isolation.prepare_reset, см. GLOBAL_FIXES #1);
  2) создаёт <out_dir>/<name>/ и валит туда ВЕСЬ вывод тулы (родные файлы + stdout/stderr/meta);
  3) запускает тулу в ЕЁ venv, наведённую на цель, с output-folder = подпапка;
  4) БЕЗОПАСНО ждёт (таймаут, не роняет оркестратор);
  5) опц. просит сильную LLM свести отчёт по файлам в наш формат (report__<name>.{json,md}).

Подкласс реализует build_invocation() (как звать тулу) и, при желании, target_env()/clean_stand().
"""

import json
import os
import subprocess
import time


class ToolWrapper:
    name = "base"                      # имя тулы == имя подпапки вывода
    default_timeout_s = 900

    # --- конфиг тулы из models.yaml (generators.<name>) — venv/таймаут/параметры ---
    def tool_cfg(self, cfg):
        return (getattr(cfg, "models", {}) or {}).get("generators", {}).get(self.name, {}) or {}

    def venv_python(self, cfg):
        return self.tool_cfg(cfg).get("venv_python")

    # --- очистка стенда (GLOBAL_FIXES #1: должна быть команда в конфиге) -----------
    def clean_stand(self, cfg, log=None):
        """Очистить память стенда перед прогоном тулы. Пока — тестовый очиститель
        isolation.prepare_reset(full=True); если в конфиге появится stand.clean_cmd — звать её."""
        cmd = (cfg.target.get("stand", {}) or {}).get("clean_cmd")
        if cmd:
            try:
                subprocess.run(cmd, shell=True, timeout=120, capture_output=True, text=True)
                if log:
                    log(event="stand_clean", via="config_cmd")
                return
            except Exception as e:
                if log:
                    log(event="stand_clean_error", via="config_cmd", error=str(e)[:200])
        # фолбэк: текущий тестовый очиститель
        try:
            from ..core import isolation
            res = isolation.prepare_reset(cfg, full=True)
            if log:
                log(event="stand_clean", via="isolation.prepare_reset", removed=res.get("removed"))
        except Exception as e:
            if log:
                log(event="stand_clean_error", via="isolation.prepare_reset", error=str(e)[:200])

    # --- подкласс переопределяет ---------------------------------------------------
    def available(self, cfg) -> bool:
        vp = self.venv_python(cfg)
        return bool(vp) and os.path.exists(vp)

    def build_invocation(self, cfg, tool_dir, args):
        """-> (argv:list[str], env:dict|None, cwd:str|None). Как звать тулу, наведённую на цель,
        с выводом в tool_dir. Подкласс обязан реализовать."""
        raise NotImplementedError

    def target_env(self, cfg):
        """Доп. env для тулы (ключи/базовые URL цели). По умолчанию — пусто."""
        return {}

    # --- единый безопасный запуск --------------------------------------------------
    def run(self, cfg, out_dir, args=None, log=None):
        """Полный жизненный цикл обёртки. НИКОГДА не бросает — возвращает summary-dict."""
        args = args or {}
        tool_dir = os.path.join(out_dir, self.name)
        os.makedirs(tool_dir, exist_ok=True)
        try:
            target_model = cfg.target_model_current()
        except Exception:
            target_model = None
        # АТРИБУЦИЯ: какую модель-мозг цели тестировали в этом прогоне (штампуем в meta)
        summary = {"tool": self.name, "dir": tool_dir, "ok": False, "target_model": target_model}
        if log:
            log(event="wrapper_target_model", tool=self.name, target_model=target_model)

        # (0) доступность тулы
        if not self.available(cfg):
            summary["status"] = "unavailable"
            summary["error"] = f"venv не найден: {self.venv_python(cfg)}"
            self._write_meta(tool_dir, summary)
            if log:
                log(event="wrapper_unavailable", tool=self.name, venv=self.venv_python(cfg))
            return summary

        # (1) очистка стенда (skip_clean — только для смоука механики без цели)
        if not args.get("skip_clean"):
            self.clean_stand(cfg, log=log)

        # (2) команда запуска
        try:
            argv, env, cwd = self.build_invocation(cfg, tool_dir, args)
        except Exception as e:
            summary["status"] = "build_error"
            summary["error"] = f"{type(e).__name__}: {str(e)[:200]}"
            self._write_meta(tool_dir, summary)
            if log:
                log(event="wrapper_build_error", tool=self.name, error=summary["error"])
            return summary

        full_env = dict(os.environ)
        full_env.update(self.target_env(cfg))
        if env:
            full_env.update(env)
        timeout = int(args.get("timeout_s") or self.tool_cfg(cfg).get("timeout_s") or self.default_timeout_s)

        # (3+4) безопасный запуск + ожидание; сырой вывод -> файлы
        t0 = time.time()
        rc, timed_out, err = None, False, None
        try:
            proc = subprocess.run(argv, env=full_env, cwd=cwd, input=args.get("stdin"),
                                  capture_output=True, text=True, timeout=timeout)
            rc = proc.returncode
            with open(os.path.join(tool_dir, "stdout.log"), "w", encoding="utf-8") as f:
                f.write(proc.stdout or "")
            with open(os.path.join(tool_dir, "stderr.log"), "w", encoding="utf-8") as f:
                f.write(proc.stderr or "")
        except subprocess.TimeoutExpired as e:
            timed_out = True
            err = f"timeout>{timeout}s"
            with open(os.path.join(tool_dir, "stdout.log"), "w", encoding="utf-8") as f:
                f.write((e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""))
            with open(os.path.join(tool_dir, "stderr.log"), "w", encoding="utf-8") as f:
                f.write((e.stderr or b"").decode() if isinstance(e.stderr, bytes) else (e.stderr or ""))
        except Exception as e:                                 # запуск не удался — не роняем оркестратор
            err = f"{type(e).__name__}: {str(e)[:200]}"

        dur = round(time.time() - t0, 1)
        out_files = sorted(os.listdir(tool_dir))
        summary.update({"status": "ran", "returncode": rc, "timed_out": timed_out,
                        "error": err, "duration_s": dur, "argv": argv, "files": out_files,
                        "ok": (err is None and not timed_out)})
        self._write_meta(tool_dir, summary)
        if log:
            log(event="wrapper_ran", tool=self.name, rc=rc, timed_out=timed_out,
                duration_s=dur, files=len(out_files), error=err)

        # (5) опц. LLM-отчёт по файлам -> наш формат
        if args.get("llm_report", True):
            try:
                from . import llm_report
                rep = llm_report.build(tool_dir, cfg, tool=self.name, log=log)
                summary["llm_report"] = rep
            except Exception as e:
                summary["llm_report_error"] = f"{type(e).__name__}: {str(e)[:200]}"
                if log:
                    log(event="wrapper_llm_report_error", tool=self.name, error=summary["llm_report_error"])
        return summary

    @staticmethod
    def _write_meta(tool_dir, summary):
        try:
            with open(os.path.join(tool_dir, "meta.json"), "w", encoding="utf-8") as f:
                json.dump(summary, f, ensure_ascii=False, indent=2)
        except Exception:
            pass


# --- реестр обёрток (заполняется при импорте подмодулей) --------------------------
WRAPPERS = {}


def register(cls):
    WRAPPERS[cls.name] = cls
    return cls


def available_wrappers():
    return sorted(WRAPPERS)


def get_wrapper(name):
    return WRAPPERS.get(name)
