"""Optional AI/ML library integrations (runtime-detected, graceful fallback).

Heavyweight third-party libraries are never imported at module load and are
probed at call time, so the AEGIS core stays offline and dependency-free. When a
library is absent, the integration returns a structured *unavailable* result
naming the install command and the inputs it needs; when present, the wrapper
invokes it and normalises the output. This mirrors how the explainability layer
treats TransformerLens/SHAP/Captum.

See :mod:`aegis.integrations.libraries` for the registry and runners.
"""

from __future__ import annotations

from .libraries import (
    LIBRARIES,
    LibrarySpec,
    availability,
    describe,
    run,
)

__all__ = ["LIBRARIES", "LibrarySpec", "availability", "describe", "run"]
