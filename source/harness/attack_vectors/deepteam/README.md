# deepteam (обёртка над внешним инструментом)

Запускает настоящий `deepteam` (`deepteam run`) в его собственном venv, нацеленный на нашу цель
через callback-файл (`model_callback` обращается к `/v1/chat/completions`). Симулятор атак и судья
(deepeval) — это наш OpenRouter (`OPENAI_BASE_URL`). Вывод сводит в наш стандартный формат сильная
модель со скептической перепроверкой.

- **Тип:** `is_wrapper=True` (входит в `a-all`, но не в `a-all-nowrapper`). Меняет состояние стенда
  (`mutates_state=True`), поэтому драйвер берёт `stand_lease`.
- **Движок:** `source/harness/tool_wrappers/deepteam.py`. Сам модуль — тонкая прокладка `ToolVector`
  (`_toolbase.py`).
- **Наведение, venv и модели:** из `config/target.yaml` и `config/models.yaml` (`generators.deepteam`).

## Запуск
```bash
run.py a-deepteam                                   # ExcessiveAgency + PromptInjection по цели
run.py a-deepteam deepteam--attacks_per_vuln=2      # больше атак на уязвимость
run.py a-deepteam deepteam--simulator=deepseek/deepseek-v4-flash
```

## Выход
`runs/<прогон>/deepteam/report__deepteam.{json,md}` (наш стандарт, пишет драйвер) — его подхватывает
`run.py report`. Сырой отчёт об оценке риска и результат перепроверки лежат в
`runs/<прогон>/deepteam/deepteam/`. Находка считается показанной (`demonstrated`) только если
независимая перепроверка дала `confirmed`.

> Вердикт перепроверки — это предположение вспомогательной модели, а не проверка по фактам; находки
> обёрток не входят в список подтверждённых уязвимостей стенда (его дают векторы с проверкой по
> фактам: bac, docinject, directinject, chain, a05).
