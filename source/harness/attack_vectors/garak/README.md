# garak (обёртка над внешним инструментом)

Запускает настоящий `garak` в его собственном venv, нацеленный на нашу цель (REST-генератор
обращается к `/v1/chat/completions`), и сводит вывод в наш стандартный формат сильной моделью со
скептической перепроверкой: она подтверждает или отбраковывает находки инструмента.

- **Тип:** `is_wrapper=True` (входит в `a-all`, но не в `a-all-nowrapper`). Меняет состояние стенда
  (`mutates_state=True`) — чистит память стенда перед прогоном, поэтому драйвер берёт `stand_lease`.
- **Движок:** `source/harness/tool_wrappers/garak.py` (плюс `base.py`, `llm_report.py`). Сам модуль —
  тонкая прокладка `ToolVector` (`attack_vectors/_toolbase.py`).
- **Наведение на цель:** URL, ключ и `auth_mode` — из `config/target.yaml` (без зашитых значений).
  venv — из `config/models.yaml` (`generators.garak.venv_python`).

## Запуск
```bash
run.py a-garak                                  # latentinjection по цели, отчёт с перепроверкой
run.py a-garak garak--probes=promptinject       # другой набор проб
run.py a-garak garak--prompt_cap=2              # меньше промптов (быстрее)
run.py a-garak garak--model_type=test.Blank garak--skip_clean=true   # проверка механики без цели
```

## Выход
`runs/<прогон>/garak/` — наш `report__garak.{json,md}` (схема `attack_vector_report/1`, пишет драйвер),
его подхватывает `run.py report`. Сырой вывод инструмента и результат перепроверки — в подпапке
`runs/<прогон>/garak/garak/`. Находка считается показанной (`demonstrated`) только если независимая
перепроверка дала `confirmed` (собственный вердикт инструмента — отдельно).

> Вердикт перепроверки — это предположение вспомогательной модели, а не проверка по фактам; находки
> обёрток не входят в список подтверждённых уязвимостей стенда (его дают векторы с проверкой по
> фактам: bac, docinject, directinject, chain, a05).
