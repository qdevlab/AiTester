# Вектор `directinject_oracle` — directinject с подбором формулировок по результату проверки

Прямая доставка, как в `directinject`, плюс направленный поиск по результату проверки, как в
`docinject_oracle`: варианты — это прямые формулировки, награда считается из вердикта пробы
(`_one()`, сигналы закрепления берутся из внешнего трейсера), фазы поиска и подтверждения, удачные
варианты уходят в копилку. Модуль неактивен (`active=False`), поэтому вызывается явно:
`a-directinject_oracle`.

Механика поиска та же, что у `docinject_oracle` (общий `OracleLoopMixin`); отличается только способ
доставки (прямой запрос вместо документа) и банк формулировок `directinject.framings`.

## Запуск
```
./.venv/bin/python run.py a-directinject_oracle
./.venv/bin/python run.py a-directinject_oracle directinject_oracle--attempts=12
```
`summary.search` показывает средние награды по вариантам и выбранный `top_arm`. Полный разбор
дизайна поиска — в `../docinject/ORACLE_LOOP.md`.
