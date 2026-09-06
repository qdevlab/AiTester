"""garak как модуль-вектор (обёртка софта): движок tool_wrappers/garak -> наш report_std.

is_wrapper=True -> входит в a-all, выпадает из a-all-nowrapper. Зовётся a-garak.
Вся логика запуска/наведения на цель — в движке; здесь только привязка WRAPPER + метаданные.
"""

from .._toolbase import ToolVector
from ...tool_wrappers.garak import GarakWrapper


class GarakVector(ToolVector):
    name = "garak"
    title = "garak — latent/prompt injection (внешний атакующий модуль)"
    taxonomy = {"owasp_asi": "Prompt/Payload Injection", "owasp_llm": "LLM01 Prompt Injection"}
    hypotheses = ("H-garak-injection",)
    WRAPPER = GarakWrapper
    ARG_KEYS = ("probes", "prompt_cap", "model_type", "caller_cus",
                "timeout_s", "llm_report", "skip_clean")
