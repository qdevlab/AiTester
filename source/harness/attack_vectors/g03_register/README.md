# Вектор `g03_register` — TC-G03 регистр против отказа-контрзаписи (ось)

Directive-регистр гонит сильнее, но ловится детектором и провоцирует отказ-контрзапись; descriptive/
benign тише и обходит детектор. Прямой рычаг landing-rate — воспроизводит PromptArmor 85%→6%.

## Как это работает
Стандартный вердикт через внешний трейсер памяти (трейс-файл фиксирует закрепление на общий/личный
ярус), агрегируется отдельно по каждому регистру. Каждая успешная проба пишет трейс в `traces/`.
`directive`/`descriptive` берутся из `params.yaml`; `benign`/`compliance`/`universal` — из
`config/payloads.yaml` (`memory_poisoning`). Нет заведённого регистра → честный `no_payloads`, не ноль.

## Конфиг
Идентичность, коллекции ярусов, finalize-триггер, базовые регистры payload — из `config/*` через
`ctx.cfg`. Ноль литералов стенда.

## Параметры
См. `params.yaml`. Override: `g03_register--attempts_per_register=4`, `g03_register--registers=[...]`.

## Запуск
```
python run.py a-g03_register
python run.py --list
```

## Что кладёт в отчёт
`report__g03_register.{json,md}`. Находка `F-G03-REGISTER`, класс `poison-global`, доля + Wilson-CI,
разбивка по регистрам в notes. Таксономия: OWASP ASI06 / LLM01, ATLAS AML.T0054 / T0065 (release
2026.08). Источник: submission `catalog/CATALOG.md` (внешний submission-каталог, вне репозитория) §TC-G03.
