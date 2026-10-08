from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class AVScanResult:
    available: bool          # False when API/daemon is not reachable
    infected: bool
    virus_name: str | None
    raw_response: str
    error: str | None

class AntivirusProvider(ABC):
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider, e.g., 'clamav_rest', 'metadefender'"""
        pass

    @property
    @abstractmethod
    def provider_authority(self) -> str:
        """Type of authority: 'local_deterministic' or 'external_evidence'"""
        pass

    @abstractmethod
    def ping(self) -> bool:
        """Returns True if the provider is reachable and healthy."""
        pass

    @abstractmethod
    def get_version(self) -> str:
        """Returns the version/status string of the provider."""
        pass

    @abstractmethod
    def scan_file(self, path: str) -> AVScanResult:
        """Scans the given file and returns the result."""
        pass

