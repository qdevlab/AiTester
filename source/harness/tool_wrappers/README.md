# tool_wrappers — обёртки-раннеры внешних тул (часть комплексного инструмента)

Единый контракт: оркестратор **payload-агностичен**. Он зовёт `wrapper.run(cfg, out_dir, args)`;
обёртка сама делает всё остальное. Парсер под каждый формат вывода не пишем — сводит **сильная LLM**.

## Контракт обёртки (base.ToolWrapper)

`wrapper.run(cfg, out_dir, args, log)`:
1. создаёт `<out_dir>/<tool>/`;
2. **чистит стенд** (команда из конфига; пока — `isolation.prepare_reset(full=True)`, см. `GLOBAL_FIXES.md` #1);
3. запускает тулу в ЕЁ venv, наведённую на нашу цель, с output-folder = подпапка;
4. **безопасно ждёт** (таймаут, сырой вывод → `stdout.log`/`stderr.log`/`meta.json`, НЕ роняет оркестратор);
5. **опц.** (`args.llm_report=True`): сильная LLM читает файлы вывода и пишет `report__<tool>.{json,md}`
   в НАШЕМ формате (severity/taxonomy OWASP).

Подкласс реализует только `build_invocation(cfg, tool_dir, args) -> (argv, env, cwd)` и, при нужде,
`target_env()`/`available()`. Регистрация — декоратором `@register` (ноль ручных списков).

Оркестратор: `runner.run_tools(cfg, out_dir, tools=None|[...], args, per_tool_args)` — прогоняет
выбранные/все обёртки, пишет сводный `tools_index.json`.

## Наведение на цель

Все тулы бьют по нашему OpenAI-совместимому агенту (`cfg.agent("chat")`, Bearer `sk-genai` из
`provisioning.ensure_key`, поле `auth_mode=vulnerable`). Пути к venv тул и параметры — в
`config/models.yaml` (`generators.<tool>`), ноль литералов в коде.

## Статус тул

| tool | как запускается | наведение | статус |
|---|---|---|---|
| **garak** | `python -m garak --model_type rest -G <cfg> --probes … --report_prefix <dir>` | rest-генератор → `:9600` | **работает на цели** (latent-injection пробил цель, 2 critical/confirmed) |
| **deepteam** | `deepteam run cfg.yaml -o <dir>` | async callback-файл → `:9600`; simulator/eval → OpenRouter | **работает на цели** (ExcessiveAgency, 2 high/confirmed) |
| **llamator** | раннер-скрипт (нет CLI) в `.venv-llamator` | кастомный `ClientBase` → `:9600` (наши `auth_mode`/`session_id` + серверная память) | **работает на цели** (chat-surface: system_prompt_leakage/sycophancy/logic) |
| **promptfoo** | `promptfoo redteam run` (node) | provider-конфиг | план: кастомный email; memory-плагины облачные |
| **pyrit** | — | — | **SKIP** (по решению) |

> Столбец «статус» — **эмпирика прошлых прогонов** (пример, не факт кода и не гарантия): конкретные числа (напр. «2 critical/confirmed») получены в отдельных прогонах и зависят от цели, моделей и версий тул.

## Отчётная модель (llm_report) — это QC-слой, не транскрайбер

Судьи самих тул ШУМЯТ и дают ложноположительные (факт: llamator засчитал `broken` на явном ОТКАЗЕ
цели). Поэтому `llm_report` — не «перепиши вердикт тулы», а **скептический QC**: читает фактические
транскрипты, ставит `independent_assessment` = `confirmed|false_positive|uncertain`, снижает severity
на ложных, показывает вердикт тулы отдельно (`tool_verdict`).

**Важно:** вердикт обёртки (даже `confirmed`) — это **предположение вспомогательной QC-модели, НЕ детерминированный оракул**; находки внешних тул НЕ входят в список подтверждённых детерминированных уязвимостей стенда (там — только оракульные векторы: bac/docinject/directinject/chain/a05).

Это требует СИЛЬНОЙ модели. Слот `report` (`models.yaml`): деф. `openai/gpt-4o` (надёжный, ловит
false_positive). `gpt-4o-mini` — слаб (якорится на ярлыке тулы), только аварийный фолбэк.
`claude-sonnet-5` сильнее, но на OpenRouter упирается в `finish_reason=length` — кандидат, не дефолт.
Проверено: garak/deepteam находки → `confirmed`, llamator-отказ → `false_positive` (low).

## Запуск (пример)

```python
from harness.tool_wrappers.runner import run_tools
run_tools(cfg, run_dir, tools=["garak","deepteam"], args={"llm_report": True})
# -> run_dir/garak/…, run_dir/deepteam/…, run_dir/tools_index.json
```
