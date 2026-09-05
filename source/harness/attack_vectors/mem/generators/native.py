"""Генератор `native` — наш штатный LLM-морфер (дефолт, поведение как до прокладки).

Обёртка над Attacker.gen_poison_dialogs (core/attacker.py): по каждому регистру просит атакующую
модель сгенерировать 1..n диалогов-отравлений с плейсхолдером {marker}, подмешивая выигравшие
темплейты из корпуса как few-shot. Это ровно то, что делал run_mvp раньше — вынесено за контракт,
чтобы источник генерации переключался через params.yaml без правки кода.
"""

from .base import PoisonGenerator, normalize_specs


class NativeGenerator(PoisonGenerator):
    name = "native"

    def available(self, gctx) -> bool:
        # native — базовый источник и цель деградации: доступен ВСЕГДА. Нет ключа OpenRouter ->
        # generate() безопасно вернёт [] (статические сиды из payloads.yaml отработают выше по потоку).
        return True

    def generate(self, gctx, *, registers, n_per_register=1, seeds=None):
        atk = gctx.attacker()
        specs = []
        for reg in registers:
            try:
                dialogs = atk.gen_poison_dialogs("{marker}", register=reg,
                                                 n=n_per_register, seeds=seeds)
                for turns in dialogs:
                    specs.append({"register": reg, "turns": turns})
            except Exception as e:                       # сбой одного регистра != падение генератора
                gctx.log(event="gen_error", generator=self.name, register=reg, error=str(e)[:200])
        return normalize_specs(specs, registers)
