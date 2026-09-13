# Phishing Classifier (Phase 2b)
#
# Wraps cybersectony/phishing-email-detection-distilbert_v2.4.1, a
# DistilBERT model fine-tuned for multilabel classification of email
# text and URLs as legitimate or phishing.
#
# ---------------------------------------------------------------------------
# WHY THE LABEL MAPPING BELOW IS HARDCODED (read this before touching it)
# ---------------------------------------------------------------------------
# This checkpoint's config.json ships WITHOUT real label names. Its
# id2label block is just the transformers library default:
#
#   "id2label": {"0": "LABEL_0", "1": "LABEL_1", "2": "LABEL_2", "3": "LABEL_3"}
#
# That means `pipeline("text-classification", ...)` returns raw scores
# keyed by "LABEL_0".."LABEL_3" with no semantic meaning attached — you
# cannot recover what they mean by inspecting the model or its config.
# We had a real bug from this: the original code searched label *names*
# for the substring "phish" (`"phish" in label.lower()`), which silently
# matched nothing on every single run and made the classifier a no-op.
#
# The real mapping comes from the model author's own usage example on
# the Hugging Face model card (README), which processes the raw logits
# by fixed index position:
#
#   index 0 -> legitimate_email
#   index 1 -> phishing_url        (phishing signal)
#   index 2 -> legitimate_url
#   index 3 -> phishing_url_alt    (phishing signal)
#
# So "phishing-ness" for this model is `max(prob[1], prob[3])`, not a
# single clean "phishing" class. This is an empirical mapping taken from
# documentation, not something guaranteed by the model's internals — if
# this model is ever swapped for a different checkpoint/version, this
# mapping must be re-verified against known-good phishing and known-good
# legitimate samples before trusting its output. See LABEL_INDEX_MEANING
# below; change it in exactly one place if that ever needs to happen.
# ---------------------------------------------------------------------------

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "vidic/models/distillbert"

# Fixed index -> meaning, per the model card's own usage snippet.
# Do not reorder without re-validating against real samples.
LABEL_INDEX_MEANING = {
    0: "legitimate_email",
    1: "phishing_url",
    2: "legitimate_url",
    3: "phishing_url_alt",
}

# Which of the four output slots count as "this looks like phishing".
PHISHING_LABEL_NAMES = ("LABEL_1", "LABEL_3")

# Thresholds shared with the Risk Engine's own bucketing (Section 11),
# duplicated here only for the human-readable ClassifierResult.level.
HIGH_CONFIDENCE_THRESHOLD = 0.90
MODERATE_CONFIDENCE_THRESHOLD = 0.70


class ConfidenceLevel(str, Enum):
    """Human-readable bucket for a classifier verdict, independent of
    the exact numeric probability. Mirrors the thresholds the Risk
    Engine applies, so log lines and the UI can agree on the same
    vocabulary without importing vidic.core.risk here."""

    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNKNOWN = "unknown"  # classifier did not run / could not be interpreted


@dataclass
class ClassifierResult:
    """Outcome of running the phishing-language classifier on one email.

    `checked` is False whenever the result should NOT be trusted or
    scored — either because classification never ran (empty text,
    model load failure) or because the raw output couldn't be mapped
    to a phishing/legitimate signal (see `error`).
    """

    checked: bool = False
    phishing_probability: float = 0.0
    raw_scores: dict = field(default_factory=dict)
    error: str = ""

    @property
    def level(self) -> ConfidenceLevel:
        if not self.checked:
            return ConfidenceLevel.UNKNOWN
        if self.phishing_probability > HIGH_CONFIDENCE_THRESHOLD:
            return ConfidenceLevel.HIGH
        if self.phishing_probability >= MODERATE_CONFIDENCE_THRESHOLD:
            return ConfidenceLevel.MODERATE
        return ConfidenceLevel.LOW

    def as_summary(self) -> str:
        """One-line, human-readable summary for logs/debug output."""
        if not self.checked:
            return f"classifier: not checked ({self.error or 'unknown reason'})"
        return (
            f"classifier: {self.level.value} confidence "
            f"({self.phishing_probability:.1%}) — raw={self.raw_scores}"
        )


class PhishingClassifierError(Exception):
    """Raised only for programmer-error style misuse of this class,
    e.g. calling classify_batch with a mismatched-length argument.
    Ordinary runtime failures (model load, tokenization, etc.) are
    captured into ClassifierResult.error instead of raised, so a single
    bad email never crashes the rest of an analysis run."""


class PhishingClassifier:
    """Loads and queries the phishing-language DistilBERT model.

    The underlying HuggingFace pipeline is expensive to construct (it
    loads several hundred MB of weights from disk and initializes
    PyTorch), so it is cached at the CLASS level rather than the
    instance level: every PhishingClassifier() created with the same
    model_name reuses the same underlying pipeline object. This means
    the first classify() call in a process will be slow (disk load +
    model init); every call after that, across every instance, is fast.
    """

    _pipeline = None
    _loaded_model_name: str | None = None

    def __init__(self, model_name: str = DEFAULT_MODEL):
        self.model_name = model_name

    # -- pipeline lifecycle -------------------------------------------------

    def _get_pipeline(self):
        needs_reload = (
            PhishingClassifier._pipeline is None
            or PhishingClassifier._loaded_model_name != self.model_name
        )
        if needs_reload:
            logger.info("Loading phishing classifier model: %s", self.model_name)
            from transformers import pipeline

            PhishingClassifier._pipeline = pipeline(
                "text-classification",
                model=self.model_name,
                top_k=None,
                truncation=True,
                max_length=512,
            )
            PhishingClassifier._loaded_model_name = self.model_name
            logger.info("Phishing classifier model loaded successfully.")
        return PhishingClassifier._pipeline

    @classmethod
    def unload(cls) -> None:
        """Drops the cached pipeline so the next classify() call reloads
        from scratch. Mainly useful for tests or a future "switch model"
        settings option — not needed in normal operation."""
        cls._pipeline = None
        cls._loaded_model_name = None

    @classmethod
    def is_loaded(cls) -> bool:
        return cls._pipeline is not None

    # -- text preparation -----------------------------------------------

    @staticmethod
    def _build_text(subject: str, body: str, urls: list[str] | None) -> str:
        text = f"{subject or ''}\n\n{body or ''}".strip()
        if urls:
            text += "\n\n" + "\n".join(urls)
        return text.strip()

    # -- core classification ----------------------------------------------

    def classify(
        self,
        subject: str,
        body: str,
        urls: list[str] | None = None,
    ) -> ClassifierResult:
        """Classifies a single email's subject/body/URLs.

        Returns a ClassifierResult with checked=False (never raises) if:
          - there is no text to classify,
          - the model fails to load or run,
          - the model's raw output can't be interpreted as a phishing
            signal (see PHISHING_LABEL_NAMES above).
        """
        text = self._build_text(subject, body, urls)

        if not text:
            return ClassifierResult(checked=False, error="No text to classify")

        try:
            pipe = self._get_pipeline()
            results = pipe(text[:5000])
        except Exception as exc:  # noqa: BLE001 - never let a bad email crash analysis
            logger.warning("Phishing classifier failed to run: %s", exc)
            return ClassifierResult(checked=False, error=str(exc))

        raw_scores = self._extract_scores(results)
        return self._interpret_scores(raw_scores)

    def classify_batch(
        self,
        items: list[tuple[str, str, list[str] | None]],
    ) -> list[ClassifierResult]:
        """Convenience wrapper for classifying several emails in one call.

        Each item is a (subject, body, urls) tuple. Present for later
        phases (e.g. bulk re-scoring of History entries after a model
        upgrade) — not currently used by the main analysis flow, which
        classifies one email at a time.
        """
        return [self.classify(subject, body, urls) for subject, body, urls in items]

    # -- output interpretation -------------------------------------------

    @staticmethod
    def _extract_scores(pipeline_results) -> dict[str, float]:
        """Normalizes the pipeline's return shape into a flat
        {label_name: score} dict. `top_k=None` on the pipeline returns
        a list-of-lists (one inner list per input text); since we only
        ever pass one string, we unwrap the outer list if present."""
        scores = (
            pipeline_results[0]
            if pipeline_results and isinstance(pipeline_results[0], list)
            else pipeline_results
        )
        return {item["label"]: item["score"] for item in scores}

    @staticmethod
    def _interpret_scores(raw_scores: dict[str, float]) -> ClassifierResult:
        """Applies the fixed LABEL_1/LABEL_3 -> phishing mapping
        documented at the top of this file. See PHISHING_LABEL_NAMES."""
        phishing_scores = [
            raw_scores[label_name]
            for label_name in PHISHING_LABEL_NAMES
            if label_name in raw_scores
        ]

        if not phishing_scores:
            return ClassifierResult(
                checked=False,
                raw_scores=raw_scores,
                error=(
                    "Could not identify a phishing label among: "
                    f"{list(raw_scores.keys())}"
                ),
            )

        return ClassifierResult(
            checked=True,
            phishing_probability=max(phishing_scores),
            raw_scores=raw_scores,
        )