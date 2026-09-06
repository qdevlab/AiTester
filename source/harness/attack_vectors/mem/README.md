# Вектор `mem` — отравление многоярусной памяти

Внедряет через диалог факт/инструкцию (маркер-слово), триггерит консолидацию (`finalize`) и мерит,
куда он закрепился.

**`active=False`** — не входит в `a-all` (легаси-ядро poisoning), зовётся явно: `a-mem`.

## Как это работает
- Стадии (словами): **рабочая память** (до финализации) → **закрепление на ярус** (policy/semantic) →
  **попадание в собранный контекст** (retrieval) → **всплытие в ответе** (вопрос-ответ в новой сессии).
- **cross-tenant** (`policy`, scope=global) → critical; **within-user** (`semantic`, scope=user) →
  high. Вердикт — внешний трейсер памяти (трейс-файл) + вопрос-ответ в новом чате/от другого клиента;
  каждая успешная проба пишет трейс в `traces/`. Меряем долю + Wilson-CI (**base_rate сейчас жёстко
  обнулён** — `clean_baseline` возвращает 0).
- **Black-box**: нет mongo/redis (grey-box недоступен) → behavioral-оракул (метка в ответе новой сессии
  + rubric), находки помечаются ниже доверием (`F-POISON-BEHAVIORAL`).

State-меняющий (`mutates_state=True`): драйвер берёт lease; `run_mvp` делает точечную чистку канареек
(полный вайп — только `reset.full_wipe` в конфиге). Маркеры — обиходные слова (`fresh_marker`).

## Конфиг
`config/target.yaml`: storage (mongo коллекции/лимиты, redis), identities, finalize_triggers;
`config/payloads.yaml`: `memory_poisoning.<register>`. Ноль литералов.

## Параметры
См. `params.yaml`. Пример: `run.py a-mem mem--attempts=6 mem--registers=compliance`.

## Запуск
```
./.venv/bin/python run.py a-mem
./.venv/bin/python run.py a-mem mem--registers=benign,compliance
```

## Находки
`F-POISON-GLOBAL` (critical, cross-tenant), `F-POISON-USER` (high, within-user), при black-box —
`F-POISON-BEHAVIORAL`. Отчёты: `report__mem.{json,md}`; человекочитаемый пруф — `proof.md` в папке
прогона (`output/runs/<штамп>/<модуль>/proof.md`), плюс стабильная общая копия `output/POISON_PROOF.md`.
