

from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_MODEL ="vidic/models/distilbert"


@dataclass
class ClassifierResult:
    checked: bool = False
    phishing_probability: float = 0.0
    raw_scores: dict = field(default_factory=dict)
    error: str = ""


class PhishingClassifier:
    _pipeline = None
    _loaded_model_name = None

    def __init__(self, model_name=DEFAULT_MODEL):
        self.model_name = model_name

    def _get_pipeline(self):
        if PhishingClassifier._pipeline is None or PhishingClassifier._loaded_model_name != self.model_name:
            from transformers import pipeline
            PhishingClassifier._pipeline = pipeline(
                "text-classification",
                model=self.model_name,
                top_k=None,
                truncation=True,
                max_length=512,
            )
            PhishingClassifier._loaded_model_name = self.model_name
        return PhishingClassifier._pipeline

    def classify(self, subject, body, urls=None):
        text = f"{subject}\n\n{body}".strip()
        if urls:
            text += "\n\n" + "\n".join(urls)
        text = text.strip()

        if not text:
            return ClassifierResult(checked=False, error="No text to classify")

        try:
            pipe = self._get_pipeline()
            results = pipe(text[:5000])
        except Exception as exc:
            return ClassifierResult(checked=False, error=str(exc))

        scores = results[0] if results and isinstance(results[0], list) else results
        raw_scores = {item["label"]: item["score"] for item in scores}

        phishing_scores = [v for k, v in raw_scores.items() if "phish" in k.lower()]
        if not phishing_scores:
            return ClassifierResult(
                checked=False,
                raw_scores=raw_scores,
                error=f"Could not identify a phishing label among: {list(raw_scores.keys())}",
            )

        return ClassifierResult(checked=True, phishing_probability=max(phishing_scores), raw_scores=raw_scores)