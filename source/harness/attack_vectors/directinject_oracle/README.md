# Вектор `directinject_oracle` — directinject + oracle-in-the-loop

Прямая доставка (как `directinject`) + направленный поиск по вердикту оракула (как
`docinject_oracle`): UCB1 по профилям прямых формулировок, награда из state-оракула, SEARCH→CONFIRM,
winners → корпус. `active=False` → зовётся явно `a-directinject_oracle`.

Механика петли идентична docinject_oracle (общий `OracleLoopMixin`), отличается лишь способ доставки
(прямой запрос вместо документа) и банк `directinject.framings`.

## Запуск
```
python -m harness.orchestration.run a-directinject_oracle
python -m harness.orchestration.run a-directinject_oracle directinject_oracle--attempts=12
```
`summary.search` — средние награды по arms + top_arm. Полный дизайн петли: `../docinject/ORACLE_LOOP.md`.
