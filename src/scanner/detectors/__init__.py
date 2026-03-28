"""Detector framework for vulnerability detectors.

Each detector implements BaseDetector and is registered via @register_detector.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from scanner.bytecode.loader import ContractBytecode
from scanner.models.findings import Finding
from scanner.models.ir import ContractInfo

DETECTOR_REGISTRY: dict[str, type[BaseDetector]] = {}


class BaseDetector(ABC):
    """Abstract base for all vulnerability detectors."""

    name: str = ""
    description: str = ""

    @abstractmethod
    def detect_from_source(self, contracts: list[ContractInfo]) -> list[Finding]:
        """Run detection on source-level IR (from AST analysis)."""
        ...

    @abstractmethod
    def detect_from_bytecode(
        self, bytecodes: list[ContractBytecode], extra: dict[str, Any] | None = None
    ) -> list[Finding]:
        """Run detection on bytecode (fallback when source is unavailable)."""
        ...


def register_detector(cls: type[BaseDetector]) -> type[BaseDetector]:
    """Class decorator to register a detector by name."""
    DETECTOR_REGISTRY[cls.name] = cls
    return cls


def get_all_detectors() -> list[type[BaseDetector]]:
    """Return all registered detector classes."""
    return list(DETECTOR_REGISTRY.values())
