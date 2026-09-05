"""Вектор docinject_oracle — docinject + oracle-in-the-loop.

Доставка = документ (DELIVERY по умолчанию), планировщик = OracleLoopMixin (UCB1 по вердикту
оракула, SEARCH→CONFIG, winners→корпус). Логика целиком в общей базе; здесь — идентичность.
Дизайн: ../docinject/ORACLE_LOOP.md. active=False (тяжёлый режим, зовётся явно).
"""

from .._docbase import DocPoisonBase, OracleLoopMixin


class DocInjectOracle(OracleLoopMixin, DocPoisonBase):
    name = "docinject_oracle"
    title = "Отравление памяти через документ (oracle-in-the-loop)"
    TASK = "docinject_oracle"
    CONFIG_KEY = "docinject"
    FID = "DOCINJECT_ORACLE"
    CHANNEL = "документ на анализ -> finalize (oracle-loop)"
    DELIVERY = "document"
    active = False
