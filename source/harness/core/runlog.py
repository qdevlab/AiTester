"""Контекст прогона: папка runs/<run-id>/ + построчный лог попыток attempts.jsonl.

Одна попытка = одна строка JSONL с метками варианта (гипотеза, канал, инструмент, жертва,
формулировка, модели, режим петли, auth_mode, исход оракула). Под перепроверку.
"""

import json
import os
import time
import uuid

from .config import OUTPUT_DIR

# Указатель на ТЕКУЩИЙ прогон: одна папка на кампанию, запоминается между вызовами тулы.
# Любой a-<vector> дописывается в неё (не плодит папку на каждый запуск), report читает ИМЕННО её.
# Ротация — явная: `run.py new` (свежий штамп) или `--run <имя>` (именованная кампания).
_RUNS_DIR = os.path.join(OUTPUT_DIR, "runs")
_CURRENT = os.path.join(_RUNS_DIR, "CURRENT")
_MANIFEST = "test_info.json"                       # краткий тех-манифест прогона в папке (метка + метаданные)


def write_manifest(run_dir, **fields):
    """Создать/обновить test_info.json в папке прогона (merge полей). Служит и МЕТКОЙ «папка рабочая»
    для отчётника, и носит: command (как запускали), started/finished, selected/overrides, target."""
    data = read_manifest(run_dir) or {"schema": "run_manifest/1"}
    data.update({k: v for k, v in fields.items() if v is not None})
    os.makedirs(run_dir, exist_ok=True)
    _atomic_write(os.path.join(run_dir, _MANIFEST),
                  json.dumps(data, ensure_ascii=False, indent=2))
    return data


def read_manifest(run_dir):
    """test_info.json прогона -> dict | None (None = папка без манифеста, т.е. «не рабочий прогон»)."""
    try:
        with open(os.path.join(run_dir, _MANIFEST), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _stamp():
    return time.strftime("%Y-%m-%d_%H-%M-%S")


def _atomic_write(path, text):
    """Атомарная запись (temp в той же папке + os.replace): при ПАРАЛЛЕЛЬНЫХ агентах читатель
    (другой агент/report) никогда не видит полу-записанный файл — только старую либо новую версию."""
    tmp = f"{path}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)
    return path


def current_run_id():
    """id запомненного прогона или None."""
    try:
        with open(_CURRENT, encoding="utf-8") as f:
            return f.read().strip() or None
    except OSError:
        return None


def set_current(rid):
    """Запомнить прогон rid как текущий (его получат следующие вызовы и report)."""
    os.makedirs(_RUNS_DIR, exist_ok=True)
    with open(_CURRENT, "w", encoding="utf-8") as f:
        f.write(rid + "\n")
    return rid


def resolve_run_id(new=False, name=None):
    """id папки для ЗАПИСИ (a-<vector>/all). Обновляет CURRENT.
    name -> именованная кампания; new -> свежий штамп; иначе — запомненный CURRENT
    (а если его нет — свежий штамп). Итог: «одна папка, запоминается, передаётся остальным»."""
    if name:
        return set_current(name)
    if not new:
        rid = current_run_id()
        if rid:
            return rid
    return set_current(_stamp())


def resolve_read_run_id(run_sel=None):
    """id папки для ЧТЕНИЯ (report). run_sel (имя/путь) -> он; иначе CURRENT; иначе самый свежий
    подкаталог runs/. -> run_id | None (None = нечего читать)."""
    if run_sel:
        if os.path.isdir(os.path.join(_RUNS_DIR, run_sel)):
            return run_sel
        if os.path.isdir(run_sel):
            return os.path.basename(run_sel.rstrip("/"))
        return None
    cur = current_run_id()
    if cur and os.path.isdir(os.path.join(_RUNS_DIR, cur)):
        return cur
    if not os.path.isdir(_RUNS_DIR):
        return None
    subs = [d for d in os.listdir(_RUNS_DIR) if os.path.isdir(os.path.join(_RUNS_DIR, d))]
    if not subs:
        return None
    return max(subs, key=lambda d: os.path.getmtime(os.path.join(_RUNS_DIR, d)))


class Run:
    def __init__(self, name=None, cfg=None, dir=None):
        self.cfg = cfg
        rid = name or time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
        self.run_id = os.path.basename(dir.rstrip("/")) if dir else rid
        # dir задан -> пишем в ЛЮБУЮ переданную папку (независимый отчётник); иначе — output/runs/<rid>
        self.dir = os.path.abspath(dir) if dir else os.path.join(OUTPUT_DIR, "runs", rid)
        os.makedirs(self.dir, exist_ok=True)
        self._attempts = os.path.join(self.dir, "attempts.jsonl")
        self.t0 = time.time()

    def path(self, *parts):
        return os.path.join(self.dir, *parts)

    def attempt(self, record):
        """Записать одну попытку (dict) в attempts.jsonl."""
        record = {"ts": round(time.time(), 3), **record}
        with open(self._attempts, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record

    def write_json(self, name, obj):
        return _atomic_write(self.path(name),
                             json.dumps(obj, ensure_ascii=False, indent=2))

    def write_text(self, name, text):
        return _atomic_write(self.path(name), text)

    def read_attempts(self):
        if not os.path.exists(self._attempts):
            return []
        return [json.loads(l) for l in open(self._attempts, encoding="utf-8") if l.strip()]
