"""Markdown -> PDF для отчётов через weasyprint (HTML+CSS). Кириллица (DejaVu через fontconfig),
аккуратные таблицы, заголовки, code-блоки. Контент пишет модель-reporter, здесь только рендер.
Мягкая зависимость: при отсутствии weasyprint/markdown бросает — вызывающий ловит и оставляет MD.
"""

import markdown

_CSS = """
@page { size: A4; margin: 18mm 16mm; }
body { font-family: "DejaVu Sans", "Liberation Sans", Arial, sans-serif;
       font-size: 10.5pt; line-height: 1.45; color: #1a1a1a; }
h1 { font-size: 19pt; margin: 0 0 10pt; color: #16324f;
     border-bottom: 3px solid #2c5aa0; padding-bottom: 5pt; }
/* Разделы (## ) — цветная плашка с левым акцентом, чтобы явно отделять блоки отчёта */
h2 { font-size: 13.5pt; margin: 18pt 0 7pt; color: #163e6b;
     background: #e9f0f8; border-left: 5px solid #2c5aa0;
     padding: 5pt 8pt; border-radius: 0 3pt 3pt 0; }
/* Уязвимость / блок модуля (### ) — красный акцент (как и было) */
h3 { font-size: 12pt; margin: 13pt 0 4pt; color: #b02020;
     border-left: 3px solid #b02020; padding-left: 7pt; }
h4 { font-size: 11pt; margin: 10pt 0 3pt; color: #333; }
p  { margin: 4pt 0; }
ul, ol { margin: 4pt 0 4pt 4pt; padding-left: 14pt; }
li { margin: 1pt 0; }
strong { font-weight: bold; }
em { color: #555; }
code { font-family: "DejaVu Sans Mono", monospace; font-size: 9pt;
       background: #f1f3f5; padding: 0 2pt; border-radius: 2pt; }
/* Блок кода = РЕАЛЬНЫЙ ввод атаки в модель — янтарный акцент, чтобы бросался в глаза */
pre { background: #fff8ec; border: 1px solid #f0d9a8; border-left: 4px solid #e0900a;
      border-radius: 3pt; padding: 6pt 8pt; font-family: "DejaVu Sans Mono", monospace;
      font-size: 8.5pt; white-space: pre-wrap; }
pre code { background: transparent; padding: 0; }
/* Ответы агента / цитаты — серый акцент */
blockquote { margin: 5pt 0; padding: 3pt 8pt; border-left: 3px solid #9aa7b4;
             background: #f7f9fb; color: #333; }
table { width: 100%; border-collapse: collapse; margin: 6pt 0; font-size: 9pt; table-layout: fixed; }
th, td { border: 1px solid #c4ccd4; padding: 3pt 5pt; text-align: left; vertical-align: top;
         word-wrap: break-word; overflow-wrap: anywhere; }
th { background: #dfe7f0; color: #163e6b; font-weight: bold; }
tr:nth-child(even) td { background: #f6f8fb; }
"""


def render(md_text, pdf_path):
    """md-текст -> PDF по пути pdf_path (weasyprint). Возвращает pdf_path."""
    from weasyprint import HTML

    body = markdown.markdown(md_text, extensions=["tables", "fenced_code", "sane_lists"])
    html = (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<style>{_CSS}</style></head><body>{body}</body></html>")
    HTML(string=html).write_pdf(pdf_path)
    return pdf_path


if __name__ == "__main__":
    import sys, glob
    _cands = sorted(glob.glob("output/REPORT_*.md"))          # дефолт — свежайший REPORT_<штамп>.md
    src = sys.argv[1] if len(sys.argv) > 1 else (_cands[-1] if _cands else "output/REPORT.md")
    dst = sys.argv[2] if len(sys.argv) > 2 else src[:-3] + ".pdf"
    print("PDF ->", render(open(src, encoding="utf-8").read(), dst))
