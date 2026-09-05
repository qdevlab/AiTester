"""Оркестратор обёрток — payload-агностичный. Прогоняет выбранные/все тулы, каждую в свою подпапку.

Оркестратор НЕ знает про пайлоады: он лишь зовёт wrapper.run(cfg, out_dir, args) для каждой тулы.
Обёртка сама чистит стенд, запускает тулу в её venv на цель, валит родной вывод в <out_dir>/<tool>/
и опц. просит LLM свести отчёт. Здесь — сборка списка тул, последовательный прогон, сводный индекс.
"""

import json
import os
import time

from . import base


def run_tools(cfg, out_dir, tools=None, args=None, per_tool_args=None, log=None):
    """Прогнать тулы (по именам или все зарегистрированные) в out_dir/<tool>/.

    tools: список имён или None/"all" -> все зарегистрированные.
    args: общие аргументы для всех обёрток; per_tool_args: {tool: {...}} — точечные оверрайды.
    -> {out_dir, ran:[summary...], index_path}."""
    args = args or {}
    per_tool_args = per_tool_args or {}
    names = base.available_wrappers() if (not tools or tools == "all") else list(tools)
    os.makedirs(out_dir, exist_ok=True)

    ran = []
    for name in names:
        cls = base.get_wrapper(name)
        if cls is None:
            if log:
                log(event="tool_unknown", tool=name)
            ran.append({"tool": name, "status": "unknown"})
            continue
        a = dict(args)
        a.update(per_tool_args.get(name, {}))
        if log:
            log(event="tool_start", tool=name)
        try:
            summ = cls().run(cfg, out_dir, args=a, log=log)          # обёртка сама не бросает
        except Exception as e:                                       # но подстрахуемся ещё раз
            summ = {"tool": name, "status": "wrapper_crash", "error": f"{type(e).__name__}: {str(e)[:200]}"}
            if log:
                log(event="tool_crash", tool=name, error=summ["error"])
        ran.append({k: summ.get(k) for k in ("tool", "status", "returncode", "ok", "timed_out",
                                             "duration_s", "files", "error")} |
                   {"report": (summ.get("llm_report") or {}).get("summary")})

    index = {"schema": "tools_run/1", "target": cfg.target["target"]["name"],
             "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "out_dir": out_dir,
             "tools": names, "ran": ran}
    index_path = os.path.join(out_dir, "tools_index.json")
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
    if log:
        log(event="tools_done", n=len(ran), index=index_path)
    return {"out_dir": out_dir, "ran": ran, "index_path": index_path}


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from harness.core.config import load
    cfg = load()
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/tools-run"
    tools = sys.argv[2].split(",") if len(sys.argv) > 2 else None
    res = run_tools(cfg, out, tools=tools, args={"llm_report": True},
                    log=lambda **k: print("LOG", json.dumps(k, ensure_ascii=False)))
    print(json.dumps(res, ensure_ascii=False, indent=2))
