"""Вектор directinject — то же, что docinject, но ОБЫЧНЫМ запросом (прямая доставка).

Инструкция с кодовым словом идёт прямым сообщением клиента агенту (не внутри документа). Payload —
КОД. Остальной контур — общий (`_docbase.DocPoisonBase`); способ доставки задаётся DELIVERY="direct"
(база сама строит прямой запрос из framing). Open-loop; для управляемого поиска — directinject_oracle.
"""

from .._docbase import DocPoisonBase


class DirectInjectVector(DocPoisonBase):
    name = "directinject"
    title = "Отравление памяти прямым запросом"
    TASK = "directinject"
    CONFIG_KEY = "directinject"
    FID = "DIRECTINJECT"
    CHANNEL = "прямой запрос -> finalize"
    DELIVERY = "direct"
    active = True
    # run()/_build_message — из базы (fixed open-loop, доставка direct по DELIVERY).
