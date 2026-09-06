# Вектор `i02_sleeper` — TC-I02 отложенная активация (sleeper)

Payload инертен в текущем ходу (обходит same-turn контроль) и садится ТОЛЬКО после отложенного
`finalize`, активируясь в поздней сессии. Парный срез трейсера вокруг finalize доказывает задержку.

## Как это работает
Ход-«факт на будущее» → пред-срез трейсера `get_canary` ДО finalize (должно быть пусто) → `finalize`
→ вердикт трейсера ПОСЛЕ (landing) → всплытие в контексте поздней сессии (retrieval из трейса). Парный
`get_canary` вокруг finalize доказывает задержку. При landing на policy(global) доступен и другому
клиенту (cross-tenant). Каждая успешная проба пишет трейс в `traces/`. Зеркалит инвариант харнесса
«без finalize яд не садится».

## Конфиг
Идентичности, коллекции ярусов, finalize-триггер — из `config/target.yaml` через `ctx.cfg`.

## Параметры
См. `params.yaml`. Override: `i02_sleeper--attempts=12`, `i02_sleeper--trigger=chat_word`, `i02_sleeper--turns=[...]`.

## Запуск
```
python run.py a-i02_sleeper
python run.py --list
```

## Что кладёт в отчёт
`report__i02_sleeper.{json,md}`. Находка `F-I02-SLEEPER`, класс `poison-global`, доля закрепления
после finalize + Wilson-CI. Таксономия: OWASP ASI06 / LLM01, ATLAS AML.T0094 / T0051.002 (release
2026.08). Источник: submission `catalog/CATALOG.md` (внешний submission-каталог, вне репозитория) §TC-I02.
