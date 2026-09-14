"""Classe de base des collectors — contrat commun."""
from abc import ABC, abstractmethod


class BaseCollector(ABC):
    source: str = "base"
    category: str = "misc"

    def __init__(self, target_kind: str = "domain"):
        self.target_kind = target_kind

    def supports(self) -> bool:
        """Par défaut : supporte tous les types de cible."""
        return True

    @abstractmethod
    def collect(self, target: str) -> dict:
        """Retourne un dict normalisé {source, category, data, error}."""
        raise NotImplementedError

    @staticmethod
    def _result(source: str, category: str,
                data: dict, error: str | None = None) -> dict:
        return {"source": source, "category": category,
                "data": data or {}, "error": error}
