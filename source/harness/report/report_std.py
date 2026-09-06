"""Единый писатель отчётов НА ВЕКТОР (стандарт для сборки ядром-LLM).

Каждый вектор кладёт в папку прогона два файла с именем, кодирующим вектор:
  report__<name>.json  — строгая схема (attack_vectors.base.standard_report), машинно/для ядра.
  report__<name>.md    — человекочитаемо, единые заголовки; тело — proof вектора (что написал
                         юзер), если он есть, иначе рендер из находок.
Ядро-LLM читает все report__*.json, группирует по taxonomy/severity и собирает сводку.
"""

import os

from ..attack_vectors.base import standard_report


def write(run, vector, summary, findings, cfg):
    """-> (json_path, md_path). Пишет report__<name>.json и report__<name>.md в run.dir."""
    doc = standard_report(vector, summary, findings, cfg, run)
    json_path = run.write_json(f"report__{vector.name}.json", doc)
    md_path = run.write_text(f"report__{vector.name}.md", _md(vector, doc, run))
    return json_path, md_path


def _md(vector, doc, run):
    a = doc["attempts_summary"]
    lines = [f"# Отчёт вектора: {doc['title']}  (`{doc['vector']}`)", "",
             f"Цель: {doc['target']}  ·  сеанс: {doc['run_id']}  ·  {doc['generated']}",
             f"Меняет стейт стенда: {'да' if doc['mutates_state'] else 'нет'}  ·  "
             f"находок: {a['findings']} (воспроизведено: {a['demonstrated']})", ""]
    tx = doc.get("taxonomy") or {}
    if tx:
        lines += [f"Таксономия: OWASP ASI — {tx.get('owasp_asi', '-')}; "
                  f"OWASP LLM — {tx.get('owasp_llm', '-')}", ""]
    lines.append(f"## Находки ({a['findings']})\n")
    for f in doc["findings"]:
        lines += _md_finding(f)

    lines += _trace_section(run)

    proof = None
    try:
        proof = vector.proof(run.dir)
    except Exception:
        proof = None
    if proof and os.path.exists(proof):
        lines += ["## Что написал юзер / пруф воздействия", "",
                  open(proof, encoding="utf-8").read()]
    return "\n".join(lines)


def _md_finding(f):
    out = [f"### {f['finding_id']} — {f['goal']}  `[{f['severity']}]`  · итог: {f['outcome']}", "",
           f"- **тип:** {f['type']}"]
    tx = f.get("taxonomy") or {}
    if tx.get("owasp_asi") or tx.get("owasp_llm"):
        out.append(f"- **таксономия:** ASI {tx.get('owasp_asi', '-')} · LLM {tx.get('owasp_llm', '-')}")
    for k, v in (f.get("repro") or {}).items():
        out.append(f"- **{k}:** {v}")
    out.append(f"- **детект:** {f.get('detector')}")
    so = f.get("state_oracle") or {}
    out.append(f"- **state-оракул:** {'да' if so.get('used') else 'нет (behavioral)'}")
    r = f.get("rate")
    if r:
        out.append(f"- **доля успеха:** {r['successes']}/{r['n']} = {r['rate']} "
                   f"(95% CI {r['ci95'][0]}–{r['ci95'][1]}){' · НЕНУЛЕВОЙ' if r.get('nonzero') else ''}")
    else:
        out.append("- **метод:** детерминированный (оракул состояния), доля не применяется")
    if f.get("reason"):
        out.append(f"- **заметки:** {f['reason']}")
    out.append("")
    return out


def _trace_section(run):
    """Секция «трейсы успешных проб» (атаки на память): маркер -> куда записана канарейка -> файл в traces/.
    Строится из attempts.jsonl (поле trace_path). Нет трейсов -> секция не выводится."""
    import json
    path = os.path.join(run.dir, "attempts.jsonl")
    if not os.path.exists(path):
        return []
    rows = []
    for line in open(path, encoding="utf-8"):
        try:
            d = json.loads(line)
        except (ValueError, TypeError):
            continue
        tp = d.get("trace_path")
        if not tp:
            continue
        rel = os.path.relpath(tp, run.dir) if os.path.isabs(tp) else tp
        tv = d.get("tracer_verdict") or {}
        top = tv.get("top") or {}
        where = f"{top.get('tier')}/{top.get('scope')}" if top else "?"
        methods = ", ".join(f"{L.get('method')}({L.get('field')})" for L in tv.get("landings", [])) or "?"
        rows.append((d.get("marker", "?"), where, methods, rel))
    if not rows:
        return []
    out = ["## Трейсы успешных проб (где уязвимость)", "",
           "Каждая успешная проба атаки на память сохраняет трейс в `traces/`. Открой файл, чтобы увидеть, "
           "каким методом хранилища памяти и в какой ярус записана канарейка — это и есть место уязвимости.", ""]
    for marker, where, methods, rel in rows:
        out.append(f"- `{marker}` → закрепление в **{where}** через `{methods}` — трейс: `{rel}`")
    out.append("")
    return out
