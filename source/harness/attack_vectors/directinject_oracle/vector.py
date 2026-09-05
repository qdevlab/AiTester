"""Вектор directinject_oracle — directinject + oracle-in-the-loop.

Прямая доставка (DELIVERY="direct") + планировщик OracleLoopMixin (UCB1 по вердикту оракула,
SEARCH→CONFIRM, winners→корпус). Тонкий наследник: доставка из directinject, петля из базы.
active=False (зовётся явно a-directinject_oracle). Дизайн петли: ../docinject/ORACLE_LOOP.md.
"""

from .._docbase import DocPoisonBase, OracleLoopMixin


class DirectInjectOracle(OracleLoopMixin, DocPoisonBase):
    name = "directinject_oracle"
    title = "Отравление памяти прямым запросом (oracle-in-the-loop)"
    TASK = "directinject_oracle"
    CONFIG_KEY = "directinject"
    FID = "DIRECTINJECT_ORACLE"
    CHANNEL = "прямой запрос -> finalize (oracle-loop)"
    DELIVERY = "direct"
    active = False
