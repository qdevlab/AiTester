"""Markdown -> PDF для отчётов через weasyprint (HTML+CSS). Кириллица (DejaVu через fontconfig),
аккуратные таблицы, заголовки, code-блоки. Контент пишет модель-reporter, здесь только рендер.
Мягкая зависимость: при отсутствии weasyprint/markdown бросает — вызывающий ловит и оставляет MD.
"""

import markdown

_CSS = """
@page { size: A4; margin: 18mm 16mm; }
body { font-family: "DejaVu Sans", "Liberation Sans", Arial, sans-serif;
       font-size: 10.5pt; line-height: 1.45; color: #1a1a1a; }
h1 { font-size: 19pt; margin: 0 0 8pt; border-bottom: 2px solid #444; padding-bottom: 4pt; }
h2 { font-size: 14pt; margin: 16pt 0 6pt; border-bottom: 1px solid #bbb; padding-bottom: 2pt; }
h3 { font-size: 12pt; margin: 12pt 0 4pt; color: #b02020; }
h4 { font-size: 11pt; margin: 10pt 0 3pt; }
p  { margin: 4pt 0; }
ul, ol { margin: 4pt 0 4pt 4pt; padding-left: 14pt; }
li { margin: 1pt 0; }
strong { font-weight: bold; }
em { color: #555; }
code { font-family: "DejaVu Sans Mono", monospace; font-size: 9pt;
       background: #f4f4f4; padding: 0 2pt; border-radius: 2pt; }
pre { background: #f4f4f4; border: 1px solid #ddd; border-radius: 3pt; padding: 6pt;
      font-family: "DejaVu Sans Mono", monospace; font-size: 8.5pt; white-space: pre-wrap; }
table { width: 100%; border-collapse: collapse; margin: 6pt 0; font-size: 9pt; }
th, td { border: 1px solid #bbb; padding: 3pt 5pt; text-align: left; vertical-align: top;
         word-wrap: break-word; }
th { background: #eef1f4; font-weight: bold; }
tr:nth-child(even) td { background: #fafbfc; }
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
    import sys
    src = sys.argv[1] if len(sys.argv) > 1 else "output/VULN_REPORT.md"
    dst = sys.argv[2] if len(sys.argv) > 2 else "output/VULN_REPORT.pdf"
    print("PDF ->", render(open(src, encoding="utf-8").read(), dst))
