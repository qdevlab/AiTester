# deepteam (обёртка софта)

Запускает нативный **deepteam** (`deepteam run`) в его venv, наведённый на нашу цель через
callback-файл (`model_callback` → `/v1/chat/completions`). Симулятор атак и судья (deepeval) — наш
OpenRouter (`OPENAI_BASE_URL`). Вывод сводит сильная LLM в наш стандарт (скептический QC).

- **Тип:** `is_wrapper=True` (в `a-all`, не в `a-all-nowrapper`). `mutates_state=True` → драйвер берёт `stand_lease`.
- **Движок:** `source/harness/tool_wrappers/deepteam.py`. Модуль — прокладка `ToolVector` (`_toolbase.py`).
- **Наведение/venv/модели:** из `config/target.yaml` + `config/models.yaml` (`generators.deepteam`).

## Запуск
```bash
run.py a-deepteam                                   # ExcessiveAgency + PromptInjection по цели
run.py a-deepteam deepteam--attacks_per_vuln=2      # больше атак на уязвимость
run.py a-deepteam deepteam--simulator=deepseek/deepseek-v4-flash
```

## Выход
`runs/<прогон>/deepteam/report__deepteam.{json,md}` (наш стандарт, драйвер) — подхватывается
`run.py report`. Сырой risk-assessment + QC — в `runs/<прогон>/deepteam/deepteam/`.
Находка = `demonstrated` только при независимой QC-оценке `confirmed`.
