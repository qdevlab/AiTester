"""Реестр генераторов payload'ов + выбор источника с graceful degrade.

Выбор задаётся параметром вектора `generator` (params.yaml / CLI `mem--generator=deepteam`), без
правки кода. Неизвестное имя или недоступный тул -> откат на `native` со следом в attempts.jsonl.
Импорт обёрток тул — ЛЕНИВЫЙ: сбой импорта сторонней обёртки не ломает native-путь.
"""

from .base import GenContext, PoisonGenerator, normalize_specs
from .native import NativeGenerator


def _load_deepteam():
    from .deepteam import DeepteamGenerator
    return DeepteamGenerator


def _load_garak():
    from .garak import GarakGenerator
    return GarakGenerator


# name -> фабрика класса (ленивая, чтобы тяжёлые/сбойные обёртки не роняли реестр)
_FACTORIES = {
    "native": lambda: NativeGenerator,
    "deepteam": _load_deepteam,
    "garak": _load_garak,
}


def available_generators():
    return sorted(_FACTORIES)


def build_generator(name, gctx: GenContext) -> PoisonGenerator:
    """Собрать генератор по имени с двойным graceful degrade:
      (1) неизвестное имя или сбой импорта обёртки -> native;
      (2) обёртка есть, но тул/venv/ключ недоступны (available()=False) -> native.
    Любой откат оставляет след в attempts.jsonl."""
    name = (name or "native").strip()
    factory = _FACTORIES.get(name)
    if factory is None:
        gctx.log(event="generator_unknown", requested=name, fallback="native",
                 known=available_generators())
        return NativeGenerator()
    try:
        cls = factory()
    except Exception as e:                               # сбой импорта обёртки -> native
        gctx.log(event="generator_import_error", generator=name, error=str(e)[:200], fallback="native")
        return NativeGenerator()
    gen = cls()
    try:
        ok = gen.available(gctx)
    except Exception as e:
        gctx.log(event="generator_available_error", generator=name, error=str(e)[:200], fallback="native")
        ok = False
    if not ok:
        gctx.log(event="generator_unavailable", generator=name, fallback="native")
        return NativeGenerator()
    return gen
