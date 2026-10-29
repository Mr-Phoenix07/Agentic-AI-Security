"""Registry + runners for the optional AI/ML library integrations.

Each :class:`LibrarySpec` describes one library: its pip package, import name,
what it assesses, and the handles it needs (a model, a dataset, RAG traces, …).
Because these operate *in-process* on a model/dataset the black-box pipeline does
not hold, they are invoked explicitly by an operator (or a white-box engagement)
rather than auto-run — and every runner is defensive: a missing dependency or a
library API change yields a structured result, never a crash.

Libraries
---------
* ``giskard``    — ML/LLM vulnerability scanning (``giskard.scan``).
* ``ragas``      — RAG answer/grounding evaluation (faithfulness, relevancy…).
* ``art``        — Adversarial Robustness Toolbox: evasion/poisoning on a
                   classifier (needs white-box or query access + data).
* ``cleverhans`` — adversarial-example generation (FGSM/PGD) on a model + data.
* ``deepteam``   — LLM red-teaming built on DeepEval (needs a callback model).
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class LibrarySpec:
    name: str
    pip_package: str
    import_name: str
    domain: str                              # llm | rag | adversarial_ml
    purpose: str
    required_inputs: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def available(self) -> bool:
        """True if the library can be imported in this environment (no import)."""
        try:
            return importlib.util.find_spec(self.import_name) is not None
        except (ImportError, ValueError):
            return False

    def to_dict(self) -> dict:
        return {
            "name": self.name, "pip_package": self.pip_package,
            "import_name": self.import_name, "domain": self.domain,
            "purpose": self.purpose, "available": self.available(),
            "required_inputs": list(self.required_inputs),
            "references": list(self.references),
        }


LIBRARIES: dict[str, LibrarySpec] = {
    "giskard": LibrarySpec(
        "giskard", "giskard", "giskard", "llm",
        "Scan an ML/LLM model + dataset for vulnerabilities (bias, robustness, "
        "injection, harmfulness).",
        required_inputs=("model", "dataset"),
        references=("https://docs.giskard.ai/",)),
    "ragas": LibrarySpec(
        "ragas", "ragas", "ragas", "rag",
        "Evaluate RAG quality: faithfulness, answer relevancy, context "
        "precision/recall over (question, answer, contexts, ground_truth) rows.",
        required_inputs=("dataset",),
        references=("https://docs.ragas.io/",)),
    "art": LibrarySpec(
        "art", "adversarial-robustness-toolbox", "art", "adversarial_ml",
        "Adversarial Robustness Toolbox: craft evasion/poisoning attacks and "
        "measure a classifier's robustness.",
        required_inputs=("estimator", "x", "y"),
        references=("https://adversarial-robustness-toolbox.readthedocs.io/",)),
    "cleverhans": LibrarySpec(
        "cleverhans", "cleverhans", "cleverhans", "adversarial_ml",
        "Generate adversarial examples (FGSM/PGD) against a model to measure "
        "evasion robustness.",
        required_inputs=("model", "x", "y"),
        references=("https://github.com/cleverhans-lab/cleverhans",)),
    "deepteam": LibrarySpec(
        "deepteam", "deepteam", "deepteam", "llm",
        "LLM red-teaming (built on DeepEval): run attack vulnerabilities against "
        "a model callback and score them.",
        required_inputs=("model_callback",),
        references=("https://www.trydeepteam.com/",)),
}


def availability() -> dict[str, bool]:
    """Map every integration name to whether its library is importable."""
    return {name: spec.available() for name, spec in LIBRARIES.items()}


def describe(name: str) -> dict | None:
    spec = LIBRARIES.get(name)
    return spec.to_dict() if spec else None


def _unavailable(spec: LibrarySpec) -> dict:
    return {
        "name": spec.name, "available": False,
        "note": f"not installed — pip install {spec.pip_package}",
        "required_inputs": list(spec.required_inputs),
        "domain": spec.domain,
    }


# -- runners (reached only when the library is importable) ------------------ #
def _run_giskard(model=None, dataset=None, **_) -> dict:
    if model is None or dataset is None:
        return {"status": "needs_inputs",
                "need": "a giskard Model and Dataset (pass model=, dataset=)"}
    import giskard  # type: ignore
    report = giskard.scan(model, dataset)
    issues = getattr(report, "issues", []) or []
    return {"status": "ok", "issue_count": len(issues),
            "issues": [str(getattr(i, "group", i))[:200] for i in issues[:50]]}


def _run_ragas(dataset=None, metrics=None, **_) -> dict:
    if dataset is None:
        return {"status": "needs_inputs",
                "need": "a RAG eval dataset (question, answer, contexts, "
                        "ground_truth) via dataset="}
    from ragas import evaluate  # type: ignore
    result = evaluate(dataset) if metrics is None else evaluate(dataset, metrics=metrics)
    scores = dict(result) if hasattr(result, "keys") else {"result": str(result)[:200]}
    return {"status": "ok", "scores": scores}


def _run_art(estimator=None, x=None, y=None, attack="fgsm", eps: float = 0.1, **_) -> dict:
    if estimator is None or x is None:
        return {"status": "needs_inputs",
                "need": "an ART-wrapped estimator plus x (and y) to attack"}
    if attack == "pgd":
        from art.attacks.evasion import ProjectedGradientDescent as _Atk  # type: ignore
        adv = _Atk(estimator=estimator, eps=eps)
    else:
        from art.attacks.evasion import FastGradientMethod as _Atk  # type: ignore
        adv = _Atk(estimator=estimator, eps=eps)
    x_adv = adv.generate(x=x)
    return {"status": "ok", "attack": attack, "eps": eps,
            "adversarial_examples": int(getattr(x_adv, "shape", [len(x_adv)])[0])}


def _run_cleverhans(model=None, x=None, y=None, eps: float = 0.3, **_) -> dict:
    if model is None or x is None:
        return {"status": "needs_inputs",
                "need": "a model and inputs x (TF/JAX/Torch per cleverhans backend)"}
    # cleverhans exposes backend-specific fast_gradient_method implementations;
    # the caller picks the backend, we only confirm the entrypoint is reachable.
    import cleverhans  # type: ignore
    return {"status": "ok", "backend_hint": "use cleverhans.<tf2|torch|jax>.attacks",
            "version": getattr(cleverhans, "__version__", "?"), "eps": eps}


def _run_deepteam(model_callback=None, vulnerabilities=None, attacks=None, **_) -> dict:
    if model_callback is None:
        return {"status": "needs_inputs",
                "need": "a model_callback(prompt)->str for deepteam to red-team"}
    from deepteam import red_team  # type: ignore
    risk = red_team(model_callback=model_callback,
                    vulnerabilities=vulnerabilities or [], attacks=attacks or [])
    return {"status": "ok", "result": str(risk)[:500]}


_RUNNERS: dict[str, Callable[..., dict]] = {
    "giskard": _run_giskard, "ragas": _run_ragas, "art": _run_art,
    "cleverhans": _run_cleverhans, "deepteam": _run_deepteam,
}


def run(name: str, **handles) -> dict:
    """Run an integration if its library is importable, else return a structured
    'unavailable' result. Never raises: a library/API error is returned as data."""
    spec = LIBRARIES.get(name)
    if spec is None:
        return {"name": name, "available": False, "error": "unknown integration"}
    if not spec.available():
        return _unavailable(spec)
    try:
        out = _RUNNERS[name](**handles)
        return {"name": name, "available": True, "domain": spec.domain, **out}
    except Exception as e:  # pragma: no cover - needs the heavy dep installed
        return {"name": name, "available": True, "domain": spec.domain,
                "error": f"{type(e).__name__}: {e}"}
