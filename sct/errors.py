class SctError(ValueError):
    """Base SCT contract error."""


class EvidenceError(SctError):
    """Evidence-store or integrity contract error."""


class BenchError(SctError):
    """Prospective benchmark contract error."""
