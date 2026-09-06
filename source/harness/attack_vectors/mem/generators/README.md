# Генераторы payload'ов mem-вектора — «модуль-прокладка»

Источник payload'ов отравления — внутренняя деталь `mem`-вектора за ОДНИМ контрактом
(`base.PoisonGenerator`). Любой источник (наш морфер или обёртка сторонней тулы) отдаёт результат в
нашем формате `dialog_specs = [{register, turns:[...]}]`, где `turns` содержат плейсхолдер `{marker}`.
Всё ниже по потоку (`poison_cycle` → **трейсер памяти** → `corpus`) не меняется: вердикт по-прежнему
выносит детерминированный трейсер (трейс-файл) + вопрос-ответ, а не текст судьи.

## Контракт

```python
class PoisonGenerator:
    name = "..."
    def available(self, gctx) -> bool: ...          # тул/venv/ключ на месте? нет -> драйвер берёт native
    def generate(self, gctx, *, registers, n_per_register=1, seeds=None) -> list:
        # -> [{"register": str, "turns": ["...{marker}..."]}]; НЕ бросать (failsafe) -> [] при сбое
```

`gctx` (`GenContext`) даёт `cfg` (цель; тематика через `cfg.system_description()`), `run` (лог) и
ленивые `attacker()`/`judge()`. Выбор источника — параметр вектора `generator`
(`params.yaml` / CLI `mem--generator=<name>`), без правки кода.

## Graceful degrade (двойной)

`build_generator(name, gctx)`:
1. неизвестное имя или сбой импорта обёртки → `native` (+ след в `attempts.jsonl`);
2. обёртка есть, но тул/venv/ключ недоступны (`available()=False`) → `native`.

Плюс рантайм-фолбэк: обёртка, упавшая в подпроцессе, возвращает **native-мутации**, а статические
сиды из `payloads.yaml` в `run_mvp` добавляются в любом случае. Тула не может «уронить» прогон.

## Изоляция сторонних тул

Сторонние тулы тянут несовместимые зависимости (deepeval, torch/transformers), поэтому НЕ импортируются
в процесс харнесса, а живут в СВОЁМ venv и зовутся подпроцессом (`adapters/<tool>_adapter.py`).
Обмен — JSON stdin/stdout. Пути к venv — в `config/models.yaml` (`generators.<tool>.venv_python`),
ноль литералов в коде.

```
generators/                 адаптеры (в venv тулы)
  base.py     PoisonGenerator + GenContext + normalize_specs
  native.py   наш LLM-морфер (дефолт, поведение как до прокладки)
  deepteam.py шим -> adapters/deepteam_adapter.py  (.venv-deepteam)
  garak.py    шим -> adapters/garak_adapter.py     (.venv-garak)
adapters/
  deepteam_adapter.py   ContextPoisoning/SyntheticContextInjection; LLM-симулятор через НАШ OpenRouter
  garak_adapter.py      словарь latent-injection garak + наш payload-маркер (детерминирован)
```

## Обёрнутые источники

| generator | тула | техника | закрывает | заметка |
|---|---|---|---|---|
| `native` | — (наш морфер) | LLM-мутация по регистрам | база | дефолт; нужен ключ OpenRouter |
| `deepteam` | deepteam 1.0.9 (Apache-2.0) | ContextPoisoning / SyntheticContextInjection | **P2** (декларативное «уже одобрено / общее правило») | реальный enhance через .venv-deepteam, симулятор на нашем ключе |
| `garak` | garak 0.16.0 (Apache-2.0) | latent-injection (indirect/document) | P1-смежное / будущий doc-RAG | словарь garak + наш маркер; imperative -> ожидаемо слабее на консолидации |

Запуск:
```
run.py a-mem mem--generator=native            # дефолт
run.py a-mem mem--generator=deepteam mem--registers=universal,compliance
run.py a-mem mem--generator=garak
```

## SKIP (обёртку НЕ делаем — обоснование)

- **PyRIT** — примитив xpia (write→отложенный read) УЖЕ реализован нативно в `poison_cycle`; чистые
  конвертеры (base64/rot13/unicode) — обфускация, которая ВРЕДИТ выживанию в памяти (естественный
  язык переживает консолидацию, «салат» детектится). Плюс тяжёлый объект-модель (синглтон
  CentralMemory). Не окупается для `mem`.
- **promptfoo** — генерация memory-poisoning только через облако `api.promptfoo.app` (remote-only
  плагин, при выключенном remote отдаёт `[]`), требует аккаунт и шлёт `getUserEmail()` наружу.
  Несовместимо с самодостаточным харнессом.
- **llamator** — целевые сессии stateless (`use_history=False` в crescendo/pair/autodan_turbo/cop),
  джейлбрейк-ориентир; лицензия CC-BY-4.0 (контентная, для кода мутная). Идею strategy-library можно
  clean-room-реализовать в P4, но обёртку тулы — нет.
