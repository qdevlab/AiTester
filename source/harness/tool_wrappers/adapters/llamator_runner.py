#!/usr/bin/env python3
"""Раннер llamator — ЗАПУСКАЕТСЯ В .venv-llamator (у llamator нет CLI, только библиотека).

Читает JSON-конфиг (путь argv[1]), строит кастомный клиент цели (наши поля auth_mode/session_id +
серверная память по сессии), атакующий/судью на нашем OpenRouter, и зовёт llamator.start_testing с
текстовыми отчётами (csv/log — их читает наш llm_report). Артефакты идут в artifacts_path.

Конфиг:
  {"target": {"url","key","model","auth_field","auth_val"},
   "attacker": {"base_url","key","model"}, "judge": {..., optional},
   "tests": [["system_prompt_leakage", {"num_attempts":1,"multistage_depth":3}], ...],
   "artifacts_path": "...", "report_language": "en", "num_threads": 1}
"""

import json
import sys
import uuid

import requests

from llamator.client.chat_client import ClientBase
from llamator import ClientOpenAI, start_testing


def log(*a):
    print("[llamator-runner]", *a, file=sys.stderr, flush=True)


class TargetClient(ClientBase):
    """Наводит llamator на наш агент. Цель ИГНОРИРУЕТ массив сообщений и держит контекст серверной
    памятью по session_id (проверено), поэтому: свежая сессия на разговор (в history нет ответов
    ассистента), каждый ход шлём ТОЛЬКО новое сообщение с тем же session_id."""

    def __init__(self, url, key, model, auth_field, auth_val, model_description=None):
        self.url = url
        self.key = key
        self.model = model
        self.auth_field = auth_field
        self.auth_val = auth_val
        self.model_description = model_description or "target agent under test"
        self._sid = None

    def interact(self, history, messages):
        if self._sid is None or not any(m.get("role") == "assistant" for m in history):
            self._sid = "llamator-" + uuid.uuid4().hex[:12]        # новый разговор -> новая сессия
        text = "\n".join(m["content"] for m in messages if m.get("role") == "user")
        if not text and messages:
            text = messages[-1].get("content", "")
        body = {"model": self.model, "messages": [{"role": "user", "content": text}],
                self.auth_field: self.auth_val, "session_id": self._sid, "stream": False}
        try:
            r = requests.post(self.url, headers={"Authorization": f"Bearer {self.key}",
                              "Content-Type": "application/json"}, json=body, timeout=180)
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"] or ""
        except Exception as e:
            content = f"[target-error] {type(e).__name__}: {e}"
        return {"role": "assistant", "content": content}


def main():
    cfg = json.load(open(sys.argv[1], encoding="utf-8"))
    t = cfg["target"]
    tested = TargetClient(t["url"], t["key"], t["model"], t["auth_field"], t["auth_val"],
                          model_description=cfg.get("target_desc"))

    a = cfg["attacker"]
    attacker = ClientOpenAI(api_key=a["key"], base_url=a["base_url"], model=a["model"],
                            temperature=float(a.get("temperature", 0.9)),   # атакующий: покрытие, не детерминизм
                            model_description="attacker LLM")
    j = cfg.get("judge") or a
    judge = ClientOpenAI(api_key=j["key"], base_url=j["base_url"], model=j["model"],
                         temperature=float(j.get("temperature", 0.0)), model_description="judge LLM")

    basic_tests = [(name, params) for name, params in cfg["tests"]]
    run_cfg = {"enable_logging": True, "enable_reports": True,
               "artifacts_path": cfg["artifacts_path"],
               "report_language": cfg.get("report_language", "en"), "debug_level": 1}

    log(f"start_testing: tests={[t[0] for t in basic_tests]} artifacts={cfg['artifacts_path']}")
    result = start_testing(attack_model=attacker, tested_model=tested, config=run_cfg,
                           judge_model=judge, num_threads=int(cfg.get("num_threads", 1)),
                           basic_tests=basic_tests)
    # итог -> stdout (llm_report возьмёт csv/log из artifacts_path; это — краткая сводка)
    json.dump({"result": result, "tests": [t[0] for t in basic_tests]}, sys.stdout, ensure_ascii=False)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
