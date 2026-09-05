"""Контракт генератора payload'ов для mem-вектора (одобренный протокол «модуль-прокладка»).

Идея: генерация payload'ов отравления — ВНУТРЕННЯЯ деталь mem-вектора. Любой источник (наш
LLM-морфер, ported/шим сторонней тулы) подключается ОДНИМ интерфейсом и отдаёт результат в НАШЕМ
формате `dialog_specs`. Всё ниже по потоку (poison_cycle -> state-оракул -> corpus) не меняется:
вердикт по-прежнему выносит детерминированный оракул, а не текст.

Инварианты, которые обязан держать любой генератор:
  * НЕ выносит вердикт — только порождает варианты;
  * НЕ бросает из generate() — при сбое возвращает [] (частичный результат, failsafe);
  * config-driven — тематику берёт из cfg (system_description), ноль литералов цели;
  * turns содержат плейсхолдер "{marker}" — подстановку свежей канарейки делает pipeline.
"""

from dataclasses import dataclass, field
from typing import Any


# ── лёгкий контекст генерации (не тащим весь VectorContext) ────────────────────
@dataclass
class GenContext:
    """То, что нужно генератору: цель (cfg), лог прогона (run) и ленивые сервисы-морферы."""
    cfg: Any
    run: Any
    _attacker: Any = field(default=None, repr=False)
    _judge: Any = field(default=None, repr=False)

    def attacker(self):
        if self._attacker is None:
            from harness.core.attacker import Attacker
            self._attacker = Attacker(self.run.dir, self.cfg)
        return self._attacker

    def judge(self):
        if self._judge is None:
            from harness.oracle.judge_llm import Judge
            self._judge = Judge(self.run.dir, self.cfg)
        return self._judge

    def log(self, **fields):
        """Строка в attempts.jsonl (генератор оставляет след, не молчит)."""
        try:
            self.run.attempt(fields)
        except Exception:
            pass


# ── контракт ──────────────────────────────────────────────────────────────────
class PoisonGenerator:
    """Источник payload-спеков. Реализации: native (LLM-морфер), deepteam/garak (обёртки тул)."""

    name = "base"

    def available(self, gctx: GenContext) -> bool:
        """Готов ли источник (тул/venv/ключ на месте). False -> драйвер деградирует на native."""
        return True

    def generate(self, gctx: GenContext, *, registers, n_per_register: int = 1, seeds=None) -> list:
        """-> [{"register": str, "turns": ["...{marker}..."]}].

        turns ОБЯЗАНЫ содержать плейсхолдер "{marker}". Бросать НЕЛЬЗЯ: при сбое верни [] или
        частичный список (см. §8b контракта векторов)."""
        raise NotImplementedError


def normalize_specs(raw, registers, source=None) -> list:
    """Привести произвольный результат генератора к строгому [{register, turns:[str,...], source}].

    Терпимо к формам: [{"register","turns"}], [["t1","t2"]], ["t1"]. Гарантирует непустые turns.
    `source` — ИМЯ реально породившего генератора (провенанс для per-tool отчёта); ставит сам
    генератор, поэтому при откате (deepteam->native) тег честно скажет 'native', а не 'deepteam'."""
    out = []
    default_reg = registers[0] if registers else "benign"
    for item in (raw or []):
        reg, turns = default_reg, None
        if isinstance(item, dict):
            reg = item.get("register", default_reg)
            turns = item.get("turns")
        elif isinstance(item, list):
            turns = item
        elif isinstance(item, str):
            turns = [item]
        if not turns:
            continue
        turns = [str(t) for t in turns if str(t).strip()]
        if not turns:
            continue
        spec = {"register": reg, "turns": turns}
        if source is not None:
            spec["source"] = source
        out.append(spec)
    return out
