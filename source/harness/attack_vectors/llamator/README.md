# llamator (обёртка над внешним инструментом)

Запускает `llamator` (своего CLI у инструмента нет, поэтому движок гоняет запускающий скрипт в
`.venv-llamator`), нацеленный на нашу чат-поверхность собственным клиентом (наши `auth_mode` и
`session_id` плюс серверная память). Это red-team по чату: `system_prompt_leakage` (вскрывает общий
ярус памяти в системном промпте), `sycophancy`, `logical_inconsistencies`. Вывод сводит в наш
стандарт сильная модель со скептической перепроверкой.

- **Тип:** `is_wrapper=True` (входит в `a-all`, но не в `a-all-nowrapper`). Меняет состояние стенда
  (`mutates_state=True`), поэтому драйвер берёт `stand_lease`.
- **Движок:** `source/harness/tool_wrappers/llamator.py` (плюс `adapters/llamator_runner.py`). Сам
  модуль — тонкая прокладка `ToolVector` (`_toolbase.py`).
- **Наведение, venv и модели:** из `config/target.yaml` и `config/models.yaml` (`generators.llamator`).

## Запуск
```bash
run.py a-llamator                                   # leak/sycophancy/logic по цели
run.py a-llamator llamator--attacker=deepseek/deepseek-v4-flash
```

## Выход
`runs/<прогон>/llamator/report__llamator.{json,md}` (наш стандарт, пишет драйвер) — его подхватывает
`run.py report`. Сырой вывод инструмента (csv/log/xlsx) и результат перепроверки — в
`runs/<прогон>/llamator/llamator/`. Находка считается показанной (`demonstrated`) только если
независимая перепроверка дала `confirmed` (инструмент шумит — перепроверка отбраковывает ложные
срабатывания).

> Вердикт перепроверки — это предположение вспомогательной модели, а не проверка по фактам; находки
> обёрток не входят в список подтверждённых уязвимостей стенда (его дают векторы с проверкой по
> фактам: bac, docinject, directinject, chain, a05).
