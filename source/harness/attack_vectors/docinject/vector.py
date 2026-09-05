"""Вектор docinject — отравление памяти через ДОКУМЕНТ (indirect injection).

Простая LLM (или статик при no-LLM) пишет безобидный доменный документ; НАШ КОД внедряет в него
инструкцию с кодовым словом. Агент получает документ «на анализ» -> путаница data->instruction ->
хитрый вопрос -> finalize -> проверка ДРУГИМ ЧАТОМ. Логика — в общей базе `_docbase.DocPoisonBase`;
здесь только идентичность вектора (доставка = документ, поведение базы по умолчанию).
"""

from .._docbase import DocPoisonBase


class DocInjectVector(DocPoisonBase):
    name = "docinject"
    title = "Отравление памяти через документ"
    TASK = "docinject"
    CONFIG_KEY = "docinject"
    FID = "DOCINJECT"
    CHANNEL = "документ на анализ -> finalize"
    active = True
    # _build_message и run() — из базы (документ + fixed open-loop).
