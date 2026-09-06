# Архитектура genai-harness

Универсальный test-harness для тестирования безопасности GenAI-агентов с памятью. Документ
описывает **устройство** тулы: компоненты, потоки данных, инварианты дизайна и точки расширения.
Плейн-объяснение «на пальцах» — в `HOW_IT_WORKS.md`; находки — в `RESULTS.md`.

---

## 1. Цели дизайна (что определяет всю архитектуру)

1. **Не сшито с целью.** Все факты о цели — в `config/target.yaml` (собран из `customer_info.md`).
   В коде фактов цели нет. Перенос на другую цель = замена одного файла.
2. **Оракул состояния — рефери.** Вердикт по классу выносит детерминированная проверка состояния
   хранилищ + эталон, а не текст агента и не мнение LLM-судьи. LLM может стоять где угодно в петле,
   но линейка измерения — одна.
3. **Против ложного «безопасно».** Свип векторов и моделей-атакующих; мульти-отпечаток;
   дифференциальный судья; контроли; частота на N с доверительным интервалом. «Не воспроизведено»
   репортится как «не продемонстрировано при условиях», не как «безопасно».
4. **Изоляция прогонов.** Персистентная память переживает сессии; без уборки один прогон отравит
   следующий. Уникальная сессия + teardown канареек + опция полного сброса памяти.
5. **Темпоральность.** Отравление не мгновенно; эффект меряется как многоступенчатая конверсия
   (рабочая память сессии → консолидация в долговременную память → включение в контекст → эффект
   в ответе агента) и как частота закрепления, не булев исход.

---

## 2. Карта компонентов

```
                        ┌──────────────────────────┐
   customer_info.md ──▶ │  config/*.yaml (спек)     │  target · hypotheses · models · payloads
                        └────────────┬─────────────┘
                                     │  core/config.py — единая точка правды (резолверы)
        ┌────────────────────────────┼────────────────────────────────┐
        ▼                            ▼                                  ▼
 ┌─────────────┐            ┌──────────────────┐              ┌──────────────────┐
 │   CORE      │            │     ORACLE       │              │      TASKS        │
 │ client      │  chat/fin  │ state  (BAC+mem) │  вердикт      │ bac              │
 │ provisioning│──────────▶ │ fingerprints     │◀────────────│ memory_poison    │
 │ openrouter  │  атаки/суд │ memory_observer  │              │ chain_ab         │
 │ attacker    │            │ judge_llm        │              └────────┬─────────┘
 │ isolation   │            └──────────────────┘                       │
 └──────┬──────┘                                                       │
        │                    ┌──────────────────┐                      │
        └───────────────────▶│      RECON       │                      │
                             │ route_oracle     │  (black-box навод)   │
                             │ prompt_fuzz      │                      │
                             └──────────────────┘                      │
                                                                       ▼
                                        ┌──────────────────────────────────────┐
                                        │        ORCHESTRATION (run.py)         │
                                        │  setup → sweep(варианты) → teardown   │
                                        │  + target_matrix.py (оверлей моделей) │
                                        └───────────────────┬──────────────────┘
                                                            ▼
                                        ┌──────────────────────────────────────┐
                                        │  REPORT: findings · coverage ·        │
                                        │  susceptibility · stats (Уилсон)      │
                                        └───────────────────┬──────────────────┘
                                                            ▼
                                     runs/<id>/<module>/ : report__<name>.{json,md} · summary.json ·
                                     attempts.jsonl · traces/ · proof.md  ->  runs/<id>/ : findings · coverage · REPORT_<штамп>.{md,pdf}
```

**Слой атак — плагины `attack_vectors/`.** Каждая атака = папка `<name>/` с `vector.py` (подкласс `AttackVector`), подхват интроспекцией (`registry.py`, ноль регистрации). Оркестратор (`run.py`, грамматика `a-<name>`/`a-all`/`--report`) находит и гоняет векторы единым циклом; векторы вызывают готовые `tasks/`/`core`/`oracle`. Общие каркасы — `_docbase.py` (poison) и `_toolbase.py` (обёртки). На схеме выше — движок-ядро; плагины-векторы стоят между ORCHESTRATION и TASKS.

Цель (внешняя система) — отдельный процесс; тула взаимодействует ТОЛЬКО снаружи: HTTP-ручки
агента/данных + прямое чтение хранилищ (grey-box) + оверлей развёртывания для смены модели.

---

## 3. Модули и ответственность

| Слой | Модуль | Ответственность |
|---|---|---|
| core | `config.py` | Загрузка/валидация `config/*.yaml`; резолверы URL, идентичностей, отпечатков, инструментов, слотов моделей. Единственный, кто знает структуру спека. |
| core | `client.py` | Транспорт к агенту (chat/finalize, SSE+plain), построчный аудит `calls.jsonl`. Финализация двумя каналами (endpoint / слово в чат) с ретраями. |
| core | `provisioning.py` | Headless-выдача API-ключей (grant у IAM → ручка выдачи с bypass-заголовком → парс ключа), идемпотентный кэш. |
| core | `openrouter.py` | Вызовы OpenRouter для слотов attacker/judge; лог модели+параметров (`openrouter.jsonl`). |
| core | `attacker.py` | LLM-«мозг атаки»: генерация N формулировок (one-shot) и adaptive-мутация по ответу агента. |
| core | `isolation.py` | Уникальный `session_id`; свежая канарейка; teardown маркеров; `prepare_reset` (по умолчанию точечная `purge_all_canaries`; полный `reset_memory` — только при `reset.full_wipe`). |
| core | `runlog.py` | Контекст прогона: папка `runs/<id>/`, запись `attempts.jsonl`, артефактов. |
| oracle | `state.py` | Детерминированный оракул: BAC на слое данных (served_cross_cus, account_owner) + снимок состояния. Прямые БД-чтения канарейки памяти (`marker_landed_*`) закомментированы — вердикт по памяти даёт трейсер (см. `tracer.py`); функции сохранены как откат. |
| oracle | `fingerprints.py` | Мульти-отпечаток по эталону; фильтр ложных плюсов (эхо запроса, короткие числа). |
| oracle | `tracer.py` | `TraceAnalyzer` — разбор JSONL стороннего трассировщика памяти (проект `yaml-memory-tracer`, white-box in-process к стенду). Единственный источник вердикта о закреплении: `from_cfg`/`clear`/`get_canary`/`save_trace`/`landed`. Ярус — по МЕТОДУ записи (`save_agent_policy`→global, `save_semantics`→user). Нет файла → `None` → откат на грей-бокс. |
| oracle | `memory_observer.py` | Память как временной ряд: снимки с таймстампами + диффы. В потоке отравления ОТКЛЮЧЁН (БД-диффы не снимаются; вердикт — трейсер + Q&A); класс сохранён для оффлайн-анализа. |
| oracle | `judge_llm.py` | Дифференциальный LLM-судья (чистая ↔ отравлённая память) — мягкий сигнал, калибруется об оракул. |
| recon | `route_oracle.py` | Скрытые эндпоинты по разнице HTTP-кодов (black-box навод/автоконфиг). |
| recon | `prompt_fuzz.py` | Статический (не-LLM) мутатор кандидатов — ось сравнения с LLM-атакующим. |
| tasks | `bac.py` | Таск A: 3 канала (data-layer, agent-mediated, account-owner), свип+adaptive, пара vuln↔prot. |
| tasks | `memory_poison.py` | Таск B: стадии рабочая→долговременная память→контекст→ответ (вердикт из трейсера), продольный прогон по регистрам, landing-rate. |
| tasks | `chain_ab.py` | Связка A×B: BAC через отравлённую память. |
| vectors | `attack_vectors/<name>/` | Модуль-плагин атаки (папка = вектор): `vector.py` (подкласс `AttackVector`), `params.yaml`, `README.md`. Подхват интроспекцией — ноль регистрации. |
| vectors | `base.py` · `registry.py` | Контракт `AttackVector` + `VectorContext` (ленивые `client/attacker/judge/tracer`); discovery векторов. |
| vectors | `_docbase.py` · `_toolbase.py` | Общий каркас poison-векторов (docinject/directinject) и обёрток внешних тул. |
| orch | `run.py` | CLI-дирижёр: грамматика `a-<name>`/`a-all`/`a-all-nowrapper` + оверрайды + `--report`; discover→run(vector)→report_std. Легаси smoke/bac/poison/models/chain сохранены. |
| orch | `target_matrix.py` | Матрица целевых моделей через .env-оверлей стенда (бэкап→рестарт→прогон→восстановление). |
| report | `report_std.py` | Строгая схема `report__<name>.{json,md}` на модуль (навязана драйвером даже при падении вектора). |
| report | `synthesize.py` | Сводный `REPORT_<штамп>.{md,pdf}` по прогону (`report_name`): сильная LLM (слот `reporter`) пишет прозу/дедуп, вердикт и пер-модульная таблица — детерминированы. Ссылается на файл трассировки успешной пробы. |
| report | `pdf.py` | Рендер `REPORT_<штамп>.md` → PDF (weasyprint; мягкая зависимость). |
| report | `poison_proof.py`·`bac_proof.py`·`chain_proof.py`·`docinject_proof.py` | Человекочитаемые `proof.md` («что написал юзер» + эффект). |
| report | `findings.py`·`coverage.py`·`susceptibility.py`·`stats.py` | F-находки, матрица покрытия, сравнение моделей, доля+CI Уилсона. |

---

## 4. Поток данных

### 4а. BAC (Таск A)

```
provisioning.ensure_key(1001)                       ← ключ атакующего
        │
        ├─(канал 1: data-layer)──────────────────────────────────────────────────┐
        │   oracle.state.served_cross_cus(1001, 1003, mode)                        │
        │        token(1001) → GET data_service/clients/1003 → {200|403}           │
        │                                                                          ▼
        ├─(канал 2: agent-mediated)                                        детерминированный
        │   attacker.gen_bac_prompts(...) → client.chat(1001, "…cus=1003…")        вердикт
        │        reply → fingerprints.whose(reply, exclude=[1001], excl=prompt)    (served /
        │        adaptive: если нет утечки → attacker.adapt_bac(reply) → повтор     отпечаток)
        │                                                                          ▲
        └─(канал 3: account-owner) state.account_owner_resolves(1001, счёт) ───────┘
        │
        ▼
   report.findings  (пара vulnerable↔protected; доля на N + CI)
```

### 4б. Отравление памяти (Таск B) — многоступенчатая конверсия

Стадии словами: **рабочая память сессии → консолидация в долговременную память → включение в
контекст → эффект в ответе агента**. Вердикт о закреплении даёт **внешний трейсер** (его JSONL),
эффект — **вопрос-ответ (Q&A) в новой сессии / от другого клиента**. Прямые БД-чтения канарейки
отключены.

```
prepare_reset(cfg)                                ← точечная чистка канареек (purge_all_canaries);
                                                     полный вайп — только при reset.full_wipe
clean_reply = client.chat(victim, нейтральный_?)  ← контроль (чистая память)
tracer.clear()                                    ← удалить файл трейсера ДО пробы

цикл × N (свежий marker каждый раз):
   client.dialog(1001, payload_turns)                       → in_working_memory (лог append_turn в трейсе)
   client.finalize(1001, via=endpoint|chat_word)            ← ТРИГГЕР консолидации (иначе эффекта нет)
   v = tracer.get_canary(marker)                            ← None → трейсер молчит → откат на грей-бокс
       persisted_global = tracer.landed(v, scope="global")  ← ярус по МЕТОДУ (save_agent_policy)
       persisted_user   = tracer.landed(v, scope="user")    ←              (save_semantics)
       in_retrieved_context = v.retrieved                    ← build_context в трейсе (чтение контекста)
   reply = client.chat(target, нейтральный_?)               → spread_to_target: global→жертва, user→автор
       marker_in_reply?;  judge_llm.differential(clean_reply, reply)   → reply_influence (мягкий сигнал)
   tracer.save_trace(run.dir, tag=marker)  (если закрепилось) → traces/trace_<datetime>_<marker>.jsonl
   teardown (грей-бокс): isolation.cleanup_marker(marker)

baseline (base_rate): ОТКЛЮЧЁН — проверки только через трейс + Q&A, не через чтение БД
```

Цель распространения зависит от яруса закрепления: `global` → жертва (другой клиент);
`user` → сам автор в новой сессии (within-user persistence). Каждая УСПЕШНАЯ проба пишет трейс в
`traces/`, сводный отчёт на него ССЫЛАЕТСЯ («Файл трассировки»).

---

## 5. Три оси «где LLM в петле» (предмет эксперимента)

| Ось | Варианты | Где реализовано |
|---|---|---|
| Генерация атаки | static (payloads/prompt_fuzz) · LLM one-shot · LLM adaptive | `tasks/bac`, `attacker.py` |
| Детект успеха | детерминированный оракул (BAC) · трейсер памяти + Q&A · LLM-судья · калибровка | `oracle/state` (BAC) + `oracle/tracer` (память) + `oracle/judge_llm` |
| Оркестрация | фиксированный порядок в коде · (задел под LLM-решение шага) | `orchestration/run` |

Каждая попытка в `attempts.jsonl` помечена вариантом (канал, атакующая модель, режим), чтобы
результаты не смешивались. Роль Claude Code — только код + арбитр, НЕ участник сравнения.

---

## 6. Слои детекта и деградация

| Доступ к цели | BAC | Отравление |
|---|---|---|
| трейсер (JSONL трассировщика памяти) | — | **файл трейсера**: закрепление по МЕТОДУ (global/user) — основной источник вердикта |
| grey-box (Redis/Mongo на host) | дифф ярусов + прямое чтение | откат, если трейсер молчит (прямые БД-чтения канарейки закомментированы) |
| black-box (только чат / Q&A) | отпечатки жертвы в ответе агента | маркер в ответе жертвы (Q&A в новой сессии), дифференциально |

Режим детекта фиксируется в находке. Для текущей цели доступен grey-box (redis:16379/mongo:37017
проброшены), а память судится по **файлу трейсера** (`yaml-memory-tracer`, white-box in-process) +
Q&A. `recon/` достраивает недостающие факты вслепую, если grey-box или `customer_info` неполны.

---

## 7. Конфиг как единственная правда

`core/config.py` — фасад над `config/*.yaml`. Никакой другой модуль не знает литералов цели.

- **`target.yaml`** — endpoints, auth_modes, provisioning, finalize_triggers, storage
  (коллекции/лимиты), tools (7 чувствительных + 7 справочных), identities (эталон 1001–1005 с
  отпечатками), target_models, deployment (для оверлея модели), needs_review (пробелы).
- **`hypotheses.yaml`** — H1..H5: тип, участники, точка детекта, оси свипа (ссылки `from_target`).
- **`models.yaml`** — слоты attacker/judge/target_brain/target_consolidation + `report` (QC-сводка
  обёрток) и `reporter` (ядро-отчётник, дефолт `claude-sonnet-5`) — списки кандидатов.
- **`payloads.yaml`** — формулировки по регистрам (benign/instruction/compliance/universal),
  `{marker}`/`{account_id}` подставляются на прогоне.

Резолверы (`cfg.url()`, `cfg.fingerprints_for()`, `cfg.sensitive_tools()`, `cfg.slot()` …)
скрывают структуру; смена схемы цели затрагивает только `config.py` + yaml, не логику атак.

---

## 8. Жизненный цикл прогона и изоляция

1. `Run()` создаёт `runs/<id>/`, открывает `attempts.jsonl`.
2. Очистка: `prepare_reset()` → по умолчанию точечная `purge_all_canaries()` (по сигнатурам
   маркеров); полный `reset_memory()` (сброс ярусов, кроме `api_keys`) — только при `reset.full_wipe`
   (он клобберит со-арендаторов стенда).
3. Каждая попытка: свежий `session_id`, свежая канарейка → атака → трейсер/оракул → запись строки →
   teardown маркера.
4. Между разными формулировками отравления — точечная чистка канареек (накопление контрзаписей
   одного payload не занижает закрепление другого); внутри формулировки накопление сохраняется
   (dose-response).
5. Смена модели цели (`target_matrix`): бэкап `.env` → правка переменной → рестарт agent-api →
   ожидание health → прогон → **восстановление `.env`** в `finally` (стенд возвращается в исходное).

---

## 9. Отчётность и статистика

- **`findings.json/.md`** — главный артефакт. Поля: `id`, `class`, `severity`, `status`
  (demonstrated / not-demonstrated), `reproduction` (общий словарь канал/ярус/роль + конкретные
  параметры), `detection` (чем подтверждено), `success` (доля на N + CI Уилсона).
- **`report__<name>.{json,md}`** (на модуль) + сводный **`REPORT_<штамп>.{md,pdf}`** (`synthesize`, команда `report` / флаг `--report`; пишется в папку прогона `output/runs/<штамп>/` и в `output/`) — канонический выход прогона; `findings.json`/`coverage` — кумулятивное сырьё.
- **`coverage.md`** — что перебрано и с какой долей (чтобы «безопасно» опиралось на исчерпанный
  свип).
- **`susceptibility_*.md`** — сравнение атакующих и целевых моделей.
- **`attempts.jsonl` / `calls.jsonl` / `openrouter.jsonl`** — сырьё под независимую перепроверку.

Доля успеха всегда с доверительным интервалом (Уилсон корректен на малых N и у границ 0/1);
любой ненулевой успех выделяется отдельно от нуля.

---

## 10. Точки расширения

- **Новая цель** → `config/target.yaml` (+ `customer_info.md`), без правок кода.
- **Новый вектор атаки** → папка `attack_vectors/<name>/` (`vector.py`/`params.yaml`/`README.md`); подхват интроспекцией, ноль правок ядра (см. `ATTACK_VECTORS.md`).
- **Новая формулировка/регистр** → строка в `payloads.yaml`; новая гипотеза — в `hypotheses.yaml`.
- **Новая атакующая/целевая модель** → строка в `models.yaml` (candidates).
- **Новый внешний движок** (garak/llamator/deepteam/…) → обёртка-вектор с `is_wrapper=True` поверх `tool_wrappers/` + `_toolbase.py`; вердикт — тем же оракулом/скептическим QC.
