# llamator (обёртка софта)

Запускает **llamator** (у тулы нет CLI → движок гоняет раннер-скрипт в `.venv-llamator`), наведённый
на нашу чат-поверхность кастомным клиентом (наши `auth_mode`/`session_id` + серверная память).
Red-team чата: `system_prompt_leakage` (вскрывает глобальный ярус в системном промпте), `sycophancy`,
`logical_inconsistencies`. Вывод сводит сильная LLM в наш стандарт (скептический QC).

- **Тип:** `is_wrapper=True` (в `a-all`, не в `a-all-nowrapper`). `mutates_state=True` → драйвер берёт `stand_lease`.
- **Движок:** `source/harness/tool_wrappers/llamator.py` (+ `adapters/llamator_runner.py`). Модуль —
  прокладка `ToolVector` (`_toolbase.py`).
- **Наведение/venv/модели:** из `config/target.yaml` + `config/models.yaml` (`generators.llamator`).

## Запуск
```bash
run.py a-llamator                                   # leak/sycophancy/logic по цели
run.py a-llamator llamator--attacker=deepseek/deepseek-v4-flash
```

## Выход
`runs/<прогон>/llamator/report__llamator.{json,md}` (наш стандарт, драйвер) — подхватывается
`run.py report`. Сырой вывод тулы (csv/log/xlsx) + QC — в `runs/<прогон>/llamator/llamator/`.
Находка = `demonstrated` только при независимой QC-оценке `confirmed` (тула шумит — QC бракует ложные).

> QC-вердикт — **предположение вспомогательной модели, НЕ детерминированный оракул**; находки обёрток НЕ входят в список подтверждённых детерминированных уязвимостей стенда (его дают оракульные векторы: bac/docinject/directinject/chain/a05).
