# Генераторы полезных нагрузок для вектора `mem` (тонкая прослойка)

Источник полезных нагрузок для отравления — это внутренняя деталь вектора `mem`, спрятанная за одним
общим контрактом (`base.PoisonGenerator`). Любой источник, будь то наш собственный переписчик
(LLM-переписыватель формулировок) или обёртка над сторонним инструментом, отдаёт результат в нашем
формате `dialog_specs = [{register, turns:[...]}]`, где в `turns` есть место для подстановки
`{marker}`. Всё, что идёт дальше по обработке (`poison_cycle`, затем трейсер памяти, затем `corpus`),
не меняется: вердикт по-прежнему выносит детерминированный трейсер памяти вместе с повторным вопросом,
а не текст судьи.

## Контракт

```python
class PoisonGenerator:
    name = "..."
    def available(self, gctx) -> bool: ...          # тул/venv/ключ на месте? нет -> драйвер берёт native
    def generate(self, gctx, *, registers, n_per_register=1, seeds=None) -> list:
        # -> [{"register": str, "turns": ["...{marker}..."]}]; НЕ бросать (failsafe) -> [] при сбое
```

`gctx` (`GenContext`) даёт доступ к `cfg` (цель; тематика через `cfg.system_description()`), к `run`
(журнал) и к ленивым `attacker()` и `judge()`. Источник выбирается параметром вектора `generator`
(`params.yaml` или из командной строки `mem--generator=<name>`), править код для этого не нужно.

## Аккуратный откат (в два уровня)

`build_generator(name, gctx)` действует так:
1. неизвестное имя или сбой импорта обёртки — берётся `native` (со следом в `attempts.jsonl`);
2. обёртка есть, но инструмент, его окружение (venv) или ключ недоступны (`available()=False`) — снова
   берётся `native`.

Есть и запасной откат уже во время выполнения: обёртка, упавшая в подпроцессе, возвращает мутации
`native`, а статические затравки (seeds) из `payloads.yaml` в `run_mvp` добавляются в любом случае.
Так сторонний инструмент не может обрушить прогон.

## Изоляция сторонних инструментов

Сторонние инструменты тянут за собой несовместимые зависимости (deepeval, torch/transformers), поэтому
их не импортируют в процесс харнесса, а держат в отдельном окружении (venv) и вызывают отдельным
подпроцессом (`adapters/<tool>_adapter.py`). Обмен идёт через JSON по stdin/stdout. Пути к окружениям
заданы в `config/models.yaml` (`generators.<tool>.venv_python`), в коде ничего не зашито.

```
generators/                 адаптеры (в venv тулы)
  base.py     PoisonGenerator + GenContext + normalize_specs
  native.py   наш модель-переписчик (дефолт, поведение как до прокладки)
  deepteam.py шим -> adapters/deepteam_adapter.py  (.venv-deepteam)
  garak.py    шим -> adapters/garak_adapter.py     (.venv-garak)
adapters/
  deepteam_adapter.py   ContextPoisoning/SyntheticContextInjection; LLM-симулятор через НАШ OpenRouter
  garak_adapter.py      словарь latent-injection garak + наш payload-маркер (детерминирован)
```

## Обёрнутые источники

| generator | инструмент | техника | закрывает | заметка |
|---|---|---|---|---|
| `native` | — (свой переписчик) | переписывание по регистрам | база | по умолчанию; нужен ключ OpenRouter |
| `deepteam` | deepteam 1.0.9 (Apache-2.0) | ContextPoisoning / SyntheticContextInjection | **P2** (декларативное «уже одобрено / общее правило») | реальное усиление через .venv-deepteam, симулятор на нашем ключе |
| `garak` | garak 0.16.0 (Apache-2.0) | latent-injection (indirect/document) | P1-смежное / будущий doc-RAG | словарь garak и наш маркер; императив ожидаемо слабее переживает консолидацию |

Запуск:
```
run.py a-mem mem--generator=native            # дефолт
run.py a-mem mem--generator=deepteam mem--registers=universal,compliance
run.py a-mem mem--generator=garak
```

## Что намеренно не оборачиваем (и почему)

- **PyRIT** — примитив xpia (запись, затем отложенное чтение) уже реализован у нас нативно в
  `poison_cycle`; а чистые конвертеры (base64, rot13, unicode) — это обфускация, которая только вредит
  выживанию записи в памяти: естественный язык переживает консолидацию, а мешанина символов легко
  ловится. Вдобавок у PyRIT тяжёлая объектная модель (синглтон CentralMemory). Для `mem` не окупается.
- **promptfoo** — формулировки для отравления памяти он генерирует только через облако
  `api.promptfoo.app` (плагин работает лишь удалённо, а при выключенном удалённом режиме возвращает
  `[]`), требует аккаунт и отправляет наружу `getUserEmail()`. Это несовместимо с самодостаточным
  харнессом.
- **llamator** — целевые сессии без состояния (`use_history=False` в crescendo/pair/autodan_turbo/cop),
  уклон в джейлбрейк; лицензия CC-BY-4.0 (для контента, к коду применима неоднозначно). Идею
  библиотеки стратегий можно переписать с нуля (clean-room) в P4, но саму обёртку над инструментом —
  нет.
