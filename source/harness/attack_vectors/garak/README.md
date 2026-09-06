# garak (обёртка софта)

Запускает нативный **garak** в его venv, наведённый на нашу цель (rest-генератор → `/v1/chat/completions`),
и сводит вывод в наш стандарт через сильную LLM (скептический QC: подтверждает/бракует находки тулы).

- **Тип:** `is_wrapper=True` (в `a-all` входит, из `a-all-nowrapper` выпадает). `mutates_state=True`
  (чистит память стенда перед прогоном → драйвер берёт `stand_lease`).
- **Движок:** `source/harness/tool_wrappers/garak.py` (+ `base.py`, `llm_report.py`). Модуль — тонкая
  прокладка `ToolVector` (`attack_vectors/_toolbase.py`).
- **Наведение на цель:** URL/ключ/`auth_mode` — из `config/target.yaml` (ноль литералов). venv — из
  `config/models.yaml` (`generators.garak.venv_python`).

## Запуск
```bash
run.py a-garak                                  # latentinjection по цели, QC-отчёт
run.py a-garak garak--probes=promptinject       # другой набор проб
run.py a-garak garak--prompt_cap=2              # меньше промптов (быстрее)
run.py a-garak garak--model_type=test.Blank garak--skip_clean=true   # смоук механики без цели
```

## Выход
`runs/<прогон>/garak/` — наш `report__garak.{json,md}` (по схеме `attack_vector_report/1`, драйвер),
подхватывается `run.py report`. Сырой вывод тулы + QC — в подпапке `runs/<прогон>/garak/garak/`.
Находка = `demonstrated` только если независимая QC-оценка `confirmed` (вердикт самой тулы — отдельно).

> QC-вердикт — **предположение вспомогательной модели, НЕ детерминированный оракул**; находки обёрток НЕ входят в список подтверждённых детерминированных уязвимостей стенда (его дают оракульные векторы: bac/docinject/directinject/chain/a05).
