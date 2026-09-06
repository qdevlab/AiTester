"""Общая база для обёрток внешних тул (garak/deepteam/llamator) как модулей-векторов.

Обёртка = обычный вектор с полем is_wrapper=True. Движок (реальный запуск тулы в её venv,
наведение на цель, QC-отчёт сильной LLM) живёт в tool_wrappers/. Здесь — тонкий адаптер:
  run()      -> зовёт движок В ПАПКУ ПРОГОНА (ctx.run.dir/<tool>/), возвращает его summary;
  findings() -> мапит QC-находки движка (llm_report.independent_assessment) в наши F.finding,
                чтобы драйвер прогнал их через report_std -> конформный report__<tool>.{json,md},
                который наш synthesize читает нативно (passed/outcome/severity/taxonomy).

Подкласс задаёт только WRAPPER (класс из tool_wrappers), name/title/taxonomy и ARG_KEYS.
mutates_state=True -> драйвер берёт stand_lease вокруг run() (сериализация со стейт-векторами;
безопасно при параллельных агентах в общей папке прогона).
"""

import json

from ..report import findings as F
from .base import AttackVector


class ToolVector(AttackVector):
    is_wrapper = True              # выпадает из a-all-nowrapper, входит в a-all
    active = True
    mutates_state = True           # тула чистит/бьёт память стенда -> нужен lease (берёт драйвер)
    WRAPPER = None                 # подкласс: класс обёртки из tool_wrappers
    ARG_KEYS = ()                  # какие self.params пробрасывать в движок

    def applicable(self, ctx):
        return True                # доступность venv проверяем в run(); отчёт пишем ВСЕГДА

    def _args(self):
        return {k: self.params[k] for k in self.ARG_KEYS
                if k in self.params and self.params[k] not in (None, "")}

    def _narrative(self, summary):
        """Текст про РАБОТУ тулы для сводного отчёта (попадает даже при 0 подтверждённых находок):
        отработала ли, QC-итог сильной LLM, вердикт самой тулы, сколько находок тула заявила /
        подтвердил QC / отбраковано как ложноположительные. Это и есть «дифференциатор» в отчёте."""
        rep = (summary or {}).get("llm_report") or {}
        fs = rep.get("findings", []) or []
        conf = sum(1 for f in fs if f.get("independent_assessment") == "confirmed")
        fp = sum(1 for f in fs if f.get("independent_assessment") == "false_positive")
        unc = sum(1 for f in fs if f.get("independent_assessment") == "uncertain")
        tv = rep.get("tool_verdict")
        tv = tv if isinstance(tv, str) else (json.dumps(tv, ensure_ascii=False) if tv else "")
        p = [f"Внешняя тула **{self.name}**: status={summary.get('status')}, "
             f"{summary.get('duration_s')}s, rc={summary.get('returncode')}"
             + (", TIMEOUT" if summary.get("timed_out") else "") + "."]
        p.append("ВАЖНО: по обёрткам нет детерминированного оракула (это текст-атаки) — вердикт ниже "
                 "это ПРЕДПОЛОЖЕНИЕ второй LLM (QC перечитывает транскрипты), НЕ истина и не 'сильнее' "
                 "судьи тулы; проверяемый факт — реальные ответы цели в пер-тульном отчёте report__"
                 f"{self.name}.md.")
        if rep.get("summary"):
            p.append(f"Итог QC (предположение): {rep['summary']}")
        if tv:
            p.append(f"Вердикт самой тулы: {tv[:300]}")
        p.append(f"Заявлено тулой находок: {len(fs)}; QC-предположительно подтверждено: {conf}; "
                 f"QC считает ложноположительными (тула засчитала пробитие, но в транскрипте цель "
                 f"отказала/уклонилась): {fp}" + (f"; неопределённо: {unc}" if unc else "") + ".")
        return " ".join(p)

    def run(self, ctx):
        w = self.WRAPPER()
        summary = w.run(ctx.cfg, ctx.run.dir, args=self._args(), log=None)  # -> ctx.run.dir/<tool>/
        try:
            summary["narrative"] = self._narrative(summary)   # -> report_std -> synthesize (атрибуция тулы)
            summary["source"] = self.name
        except Exception:
            pass
        try:
            rep = summary.get("llm_report") or {}
            ctx.run.attempt({"vector": self.name, "tool": self.name,
                             "status": summary.get("status"), "ok": summary.get("ok"),
                             "returncode": summary.get("returncode"),
                             "timed_out": summary.get("timed_out"),
                             "tool_verdict": rep.get("tool_verdict"),
                             "findings": len(rep.get("findings", []) or [])})
        except Exception:
            pass
        return summary

    def findings(self, summary, ctx):
        summary = summary or {}
        rep = summary.get("llm_report") or {}
        st = summary.get("status")

        # тула не запустилась/недоступна/таймаут -> честная not-demonstrated (отчёт всё равно будет)
        if st in ("unavailable", "build_error") or summary.get("timed_out") or summary.get("error"):
            return [F.finding(
                f"F-{self.name.upper()}-RUN", self.name,
                f"Обёртка {self.name}: тула не отработала",
                {"channel": f"внешняя тула ({self.name})", "status": st,
                 "call": f"{self.name} (venv) -> цель"},
                f"status={st}; timed_out={summary.get('timed_out')}; error={summary.get('error')}",
                None, "info", status="not-demonstrated",
                notes="Внешняя тула недоступна/не запустилась — см. meta.json/stderr.log обёртки.",
                taxonomy=self.taxonomy)]

        out = []
        for i, f in enumerate(rep.get("findings", []) or [], 1):
            ia = f.get("independent_assessment")
            confirmed = ia == "confirmed"                    # только QC-подтверждённые = demonstrated
            sev = f.get("severity", "info")
            out.append(F.finding(
                f"F-{self.name.upper()}-{i}", self.name, f.get("title") or f"{self.name} finding",
                {"channel": f"внешняя тула ({self.name})",
                 "tool_verdict": rep.get("tool_verdict", ""),
                 "evidence": (f.get("evidence") or "")[:500],
                 "class": f.get("class", "")},
                f"независимая QC-оценка: {ia or 'n/a'} (вердикт тулы отдельно, см. tool_verdict)",
                None,
                sev if confirmed else "info",
                status="demonstrated" if confirmed else "not-demonstrated",
                notes=(f"{rep.get('summary', '')} | {rep.get('notes', '')}")[:600],
                taxonomy=f.get("taxonomy") or self.taxonomy))

        if not out:                                          # отработала, находок нет -> цель устояла
            out = [F.finding(
                f"F-{self.name.upper()}-CLEAN", self.name,
                f"Обёртка {self.name}: пробитий по фактам не выявлено",
                {"channel": f"внешняя тула ({self.name})", "tool_verdict": rep.get("tool_verdict", "")},
                rep.get("summary", "тула отработала, находок не выявлено"),
                None, "info", status="not-demonstrated",
                notes=rep.get("notes", ""), taxonomy=self.taxonomy)]
        return out
