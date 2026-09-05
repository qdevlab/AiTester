# AI Test CUI — модульный харнесс тестирования безопасности агентов с памятью

Конфиг-driven грей-бокс инструмент для GenAI-агента с многоярусной памятью. **Дифференциатор:**
вердикт даёт **детерминированный оракул состояния** (дифф БД/сервиса, HTTP-статусы, поведение в
НОВОМ чате), а не текст-судья — поэтому ловит BAC и отравление памяти, которые текст-судьи метят как
«чисто». LLM только **генерит/мутирует** атаки и **пишет сводный отчёт**, но НЕ судит.

Атаки — **модульные плагины**: атака = папка `attack_vectors/<name>/`, подхватывается сама (ноль
регистрации). Перенос на другой стенд = замена `source/harness/config/target.yaml`, код не трогаем.

---

## Раскладка

| путь | что |
|---|---|
| `source/harness/attack_vectors/` | **модули атак** (по папке на вектор) + `base.py`/`registry.py`/`_docbase.py` |
| `source/harness/oracle/` | детерминированный оракул: `state.py` (дифф ярусов/сервиса), `fingerprints.py`, `judge_llm.py` |
| `source/harness/core/` | `config`, `client` (агент), `attacker` (LLM-морфер), `openrouter`, `isolation`, `corpus`, `conversation` |
| `source/harness/report/` | `report_std` (стандарт `report__<name>.{json,md}`), `synthesize` (LLM-отчёт), `pdf`, proof-билдеры |
| `source/harness/orchestration/run.py` | оркестратор: грамматика `a-<name>`, generic-драйвер, `report` |
| `source/harness/config/` | `target.yaml` (правда о цели), `models.yaml` (слоты), `payloads.yaml`, `hypotheses.yaml` |
| `docs/` | `ATTACK_VECTORS.md` (как писать атаку), архитектура, методы, находки |
| `output/` | результаты (не в git): `runs/<date>/<module>/…`, сводный `VULN_REPORT.{md,pdf}` |

`.env` (`OPENROUTER_API_KEY`) и `fixtures/{keys.json,success_corpus.json}` — вне git.

---

## Установка

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt   # или: pymongo redis requests pyyaml weasyprint markdown
echo "OPENROUTER_API_KEY=sk-or-..." > .env               # ключ подхватится автоматически
```
- **Стенд** должен быть поднят (mongo/redis/agent/data-service); адреса/порты — в `config/target.yaml`.
- **PDF-отчёт** требует `weasyprint`+`markdown` (мягкая зависимость: нет — отчёт остаётся в `.md`).

---

## Как запускать

Всё через корневой `run.py` (кладёт `source/` в путь и зовёт оркестратор).

### Модульная грамматика (основная)
```bash
./.venv/bin/python run.py --list                     # реестр всех векторов + их параметры
./.venv/bin/python run.py a-bac                      # запустить один вектор
./.venv/bin/python run.py a-bac a-docinject          # несколько
./.venv/bin/python run.py a-all                      # ВСЕ активные векторы (полный прогон, вкл. обёртки)
./.venv/bin/python run.py a-all-nowrapper            # все активные БЕЗ обёрток [wrapper] (быстрое ядро)
./.venv/bin/python run.py a-docinject docinject--mode=stealth docinject--attempts=8   # override параметров
```
- **`a-<name>`** — выбрать вектор (по имени папки); **`a-all`** — все `active=True` (вкл. обёртки);
  **`a-all-nowrapper`** — все активные, но без обёрток (модули с полем `is_wrapper=True`).
- **`<name>--<key>=<value>`** — переопределить параметр этого вектора (оркестратор срезает `<name>--`,
  модуль получает чистый `key`; неизвестный ключ → варнинг, не падение). Дефолты — в `params.yaml` вектора.

### Полный цикл: прогон → сводный отчёт
```bash
./.venv/bin/python run.py a-all        # 1) все модули -> runs/<прогон>/<module>/report__<name>.{json,md}
./.venv/bin/python run.py report       # 2) свод ПО ЭТОМУ прогону -> output/VULN_REPORT.{md,pdf}
```
Неактивные векторы (см. таблицу) в `a-all` не входят — зовите явно (`a-mem`, `a-chain`, `a-docinject_oracle`, `a-directinject_oracle`).

### Одна папка прогона (важно: несколько агентов пишут в неё же)
Прогон = **одна папка** `runs/<прогон>/`. Она **запоминается** (`runs/CURRENT`) и переиспользуется
следующими вызовами и **другими агентами** — каждый модуль пишет в свою подпапку `runs/<прогон>/<module>/`,
поэтому параллельные агенты не конфликтуют, а `report` собирает всё из ЭТОЙ папки (без разъезда по датам).
```bash
./.venv/bin/python run.py new --run camp1   # начать именованную папку и запомнить её (детерминированно)
./.venv/bin/python run.py a-bac             # агент 1 -> runs/camp1/bac/        (--run не нужен: берёт CURRENT)
./.venv/bin/python run.py a-docinject       # агент 2 -> runs/camp1/docinject/  (та же папка)
./.venv/bin/python run.py where             # показать текущую папку и её модули
./.venv/bin/python run.py report            # свод по runs/camp1/ -> в неё же + output/VULN_REPORT.{md,pdf}
```
- **`run.py new [--run <имя>]`** — начать новую папку (свежий штамп даты или именованная кампания) и запомнить.
- **`--run <имя>`** на `a-*`/`report` — явно адресовать папку (несколько агентов дают ОДНО имя → пишут в одну папку, без гонок).
- **`--new`** на `a-*` — форсить свежую папку для этого прогона.
- Без флагов `a-*` берёт запомненную папку (`CURRENT`); если её нет — заводит свежую и запоминает.
- `report` пишет отчёт **в саму папку прогона** и копию в общий `output/VULN_REPORT.{md,pdf}` («последний»).

### Прочее
```bash
./.venv/bin/python run.py smoke        # без LLM: провижининг + чат + оракул + teardown
./.venv/bin/python run.py mem [--marker X]   # состояние ярусов памяти (policy=cross-tenant)
./.venv/bin/python run.py report       # пересобрать сводный отчёт из имеющихся report__*.json
# легаси-алиасы (плоский вывод): bac / poison / chain / bac-proof / poison-proof / llm-repro / models / repro
```

---

## Что поддерживает — модули атак (24)

`active` = входит в `a-all`; иначе — только явным `a-<name>`. Обёртки внешних тул (поле
`is_wrapper`) — `active`, но выпадают из `a-all-nowrapper` (быстрое ядро без внешних зависимостей).

| вектор | тип | что проверяет | оракул | active |
|---|---|---|---|---|
| `bac` | BAC | межклиентский доступ: сервис (`client_by_cus`), резолв владельца, LLM→tool | served/resolved + отпечатки, пара vuln↔prot | ✓ |
| `a05_direct_leak` | BAC | утечка чужих данных в ответе БЕЗ вызова инструмента | E4 отпечаток жертвы | ✓ |
| `docinject` | poison | отравление памяти через **документ** «на анализ» (indirect) | E2/E3 + resurf в новом чате | ✓ |
| `directinject` | poison | то же **прямым запросом** | E2/E3 + resurf | ✓ |
| `c01_explicit_command` | poison | явный императив записи (remember/from now on) | E2 semantic + E3 | ✓ |
| `c03_policy_conformant` | poison | «факт о мире» → scope=global (cross-tenant) | E2 policy + E4 у жертвы + base_rate | ✓ |
| `b03_false_precedent` | poison | ложный «прошлый успех» в эпизодической памяти | E2 episodic/dialog + E3 | ✓ |
| `f01_secret_landing` | poison | приземление секрета/PII (ghp_/AKIA/JWT/Luhn) в память | E2 секрет на ярусе + E3 | ✓ |
| `f03_prompt_extract` | poison | global-marker виден при запросе системного промпта | E3-альт у жертвы | ✓ |
| `g02_multilingual` | ось | инъекция на разных языках (обход паттерн-детекта) | E2 landing по языку | ✓ |
| `g03_register` | ось | регистр формулировки (directive↔descriptive) vs контрзапись | E2 landing по регистру | ✓ |
| `g05_cover_tracks` | poison | store-дифф ловит яд ПОСЛЕ удаления чата | E2 после заметания следов | ✓ |
| `i02_sleeper` | poison | отложенная активация (инертно до триггера/finalize) | E2 парный дифф вокруг finalize | ✓ |
| `i03_single_injection` | poison | персистентность N=1 инъекции (обход дедупа) | E2 landing + E3 позже | ✓ |
| `l03_recon` | recon | разведка инструментов/триггеров/промпта | pre-E1 пробы | ✓ |
| `minja` | poison | MINJA — инъекция в память укорочением (query-only) | приземление маркера global/user | ✓ |
| `stub` | self-test | проверка каркаса end-to-end (без стенда) | — | ✓ |
| `docinject_oracle` | poison | docinject + **oracle-in-the-loop** (UCB1 по вердикту) | E2/E3 + resurf, SEARCH→CONFIRM | — |
| `directinject_oracle` | poison | directinject + oracle-in-the-loop | то же | — |
| `mem` | poison | легаси E1..E4 по регистрам | дифф ярусов | — |
| `chain` | chain | связка A×B: чужой id через память → BAC | приземление правила + отпечатки жертвы | — |
| `garak` | wrapper | нативный garak (latent/prompt injection) по цели | вывод тулы → скептический QC сильной LLM (confirmed/false_positive) | ✓ `[wrapper]` |
| `deepteam` | wrapper | нативный deepteam (ExcessiveAgency/PromptInjection) через callback | risk-assessment → QC | ✓ `[wrapper]` |
| `llamator` | wrapper | red-team чата (prompt-leak/sycophancy/logic) | вывод тулы → QC | ✓ `[wrapper]` |

> **Обёртки** (`garak`/`deepteam`/`llamator`) = обычные модули с `is_wrapper=True`; движок в
> `source/harness/tool_wrappers/`, тонкая прокладка — `attack_vectors/_toolbase.py`. Находка →
> `demonstrated` только при независимой QC-оценке `confirmed`. Требуют venv тул (`config/models.yaml`
> `generators.*`) + поднятый стенд; при отсутствии — graceful degrade (пишут not-demonstrated отчёт).

---

## Вывод

```
output/runs/CURRENT                 # указатель на текущую папку прогона (её берут все агенты и report)
output/runs/<прогон>/               # ОДНА папка прогона (штамп даты или имя из --run); переиспользуется
  <module>/                         # подпапка на модуль (каждый агент — в свою -> без коллизий)
    report__<module>.json           # строгая схема attack_vector_report/1 (для ядра-LLM)
    report__<module>.md             # человекочитаемо + «что написал юзер»
    findings.json                   # F-shape находки модуля (для кумулятивного свода прогона)
    summary.json · attempts.jsonl · calls.jsonl · proof.md
  findings.json · findings.md · coverage.* · attempts.jsonl   # свод ПО ВСЕЙ папке (кумулятивно)
  VULN_REPORT.md / .pdf             # сводный отчёт этого прогона (команда report)
output/VULN_REPORT.md / .pdf        # копия отчёта ПОСЛЕДНЕГО прогона (общая папка output/)
```
Каждый модуль **гарантированно** пишет `report__<name>.{json,md}` (драйвер зовёт `report_std` даже при
падении вектора — тогда с error-находкой). Отрицательный результат = `not-demonstrated`, не «безопасно».
Свод папки (`findings/coverage/attempts`) пересобирается из подпапок модулей при каждом вызове —
идемпотентно, поэтому финиширующий агент восстанавливает полную картину. Записи **атомарны**
(temp + `os.replace`): параллельный агент/`report` не видит полу-записанный файл.

---

## Сводный отчёт по уязвимостям

### Где забирать
- **`output/runs/<прогон>/VULN_REPORT.{md,pdf}`** — отчёт этого прогона (в самой папке прогона).
- **`output/VULN_REPORT.{md,pdf}`** — копия отчёта ПОСЛЕДНЕГО прогона (общая папка `output/`, верхний уровень; PDF нужен `weasyprint`).
- Исходные пер-модульные отчёты (из которых он собран) — `output/runs/<прогон>/<module>/report__<name>.{json,md}`.
- Какой прогон соберётся: `--run <имя>` → он; иначе `runs/CURRENT`; иначе самый свежий. (`run.py where` — показать текущий.)

### Как формируется (конвейер)
```
1) run.py a-all           каждый модуль -> report__<name>.json (строгая схема attack_vector_report/1,
                           навязана report_std; вердикт — детерминированный оракул, не LLM)
2) run.py report                    (по ОДНОЙ папке прогона: --run / CURRENT / последний)
   ├─ synthesize.gather_latest(scope_dir)  report__<name>.json КАЖДОГО модуля ЭТОГО прогона
   ├─ фильтр                        оставляем только ПОДТВЕРЖДЁННЫЕ находки (passed/demonstrated)
   ├─ сильная модель (слот reporter=claude-sonnet-5)
   │     пишет: (1) резюме по severity + ключевые риски;
   │            (2) уязвимости — ДЕДУП (одна уязвимость на несколько модулей) + атрибуция по модулям;
   │     (при сбое LLM — детерминированный fallback из тех же данных)
   ├─ КОД дописывает                (3) пер-модульную сводку «какой модуль что нашёл» —
   │                                ДЕТЕРМИНИРОВАННО (перебор всех report__*.json, не на откуп LLM)
   ├─ -> runs/<прогон>/VULN_REPORT.md + копия output/VULN_REPORT.md
   └─ report/pdf.py (weasyprint)    md -> HTML+CSS -> runs/<прогон>/VULN_REPORT.pdf + output/VULN_REPORT.pdf
```
Ключевое: **LLM только формулирует прозу и сводит дубли; вердикт и пер-модульная таблица —
детерминированные**. Отчёт можно пересобрать когда угодно (`run.py report`) без перепрогона атак.

### Что внутри отчёта
1. **Резюме** — сколько уязвимостей по severity, ключевые риски в 2-3 предложениях.
2. **Уязвимости** — сведённые (дедуп по классу), каждая: что это + impact простыми словами, чем
   подтверждено (детерминированный оракул, доля+Wilson-CI), воспроизведение, таксономия OWASP,
   **какие модули подтвердили**.
3. **Сводка по всем модулям** — детерминированная таблица «модуль → находки» (все 20, ничего не теряется).

### Прокладки (на будущее)
Форвард-совместим с модулями-прокладками: если у модуля отчёт пишет СТОРОННЯЯ LLM, он кладёт текст в
поле `narrative` своего `report__<name>.json` — отчётник подхватит и адаптирует с атрибуцией к инструменту.

---

## Добавить свою атаку

1. Скопируй `source/harness/attack_vectors/_template/` в `attack_vectors/<name>/` (имя — `[a-z0-9_]`).
2. Заполни `vector.py` (подкласс `AttackVector`: `run()`/`findings()`), `params.yaml`, `README.md`.
3. Готово — вектор виден в `run.py --list` и запускается `a-<name>` **без правок ядра**.

Полная инструкция автора (контракт, оракул, params, failsafe, чек-лист): **`docs/ATTACK_VECTORS.md`**.
Родственные poison-векторы могут наследовать общую базу `attack_vectors/_docbase.py` (готовый контур
пробы + resurf-проверка + oracle-in-the-loop миксин).

---

## Конфиг (перенос на другую цель)

- `config/target.yaml` — **единственный источник правды о цели**: endpoints, identities (посев),
  auth_modes, ярусы памяти/лимиты, finalize-триггеры. Смена цели = правка этого файла.
- `config/models.yaml` — слоты моделей: `attacker` (морфер), `judge`, `reporter` (отчёт), `target_*`.
- `config/payloads.yaml`, `hypotheses.yaml` — формулировки/регистры и гипотезы (config-driven).
