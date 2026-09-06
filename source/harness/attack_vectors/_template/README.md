# Вектор `<name>` — TODO: одна строка сути

TODO: что атакует, какой вердикт даёт оракул, к каким целям применим.

## Как это работает
TODO: канал (data-layer / agent-mediated / finalize→память / …), что шлётся, чем подтверждается:
BAC — оракул состояния (`served_cross_cus` / отпечатки клиента);
память — внешний трейсер (трейс-файл) + вопрос-ответ моделью в новом чате / от другого юзера (resurf).

## Конфиг
Что берётся из `config/target.yaml` через `cfg` (адреса, идентичности, ярусы). Ноль литералов.

## Параметры
См. `params.yaml`. Override из CLI: `<name>--<key>=<value>` (напр. `<name>--attempts=8`).
Неизвестный ключ → варнинг, дефолт.

## Запуск
```
./.venv/bin/python run.py a-<name>
./.venv/bin/python run.py a-<name> <name>--attempts=8
./.venv/bin/python run.py --list
```

## Что кладёт в отчёт
`report__<name>.{json,md}` в папке прогона (пишет драйвер). Находки — с таксономией OWASP ASI/LLM,
долей + Wilson-CI, статусом demonstrated/not-demonstrated. Для атак на память — ещё
`traces/trace_<датавремя>_<marker>.jsonl` (трейс успешной пробы; пишет `ctx.tracer().save_trace`).

> Полная инструкция автора: `docs/ATTACK_VECTORS.md`.
