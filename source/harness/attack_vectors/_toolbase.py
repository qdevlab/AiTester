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

    def run(self, ctx):
        w = self.WRAPPER()
        summary = w.run(ctx.cfg, ctx.run.dir, args=self._args(), log=None)  # -> ctx.run.dir/<tool>/
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
