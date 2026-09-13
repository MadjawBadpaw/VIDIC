# scripts/download_model.py
from huggingface_hub import snapshot_download

snapshot_download(
    repo_id="cybersectony/phishing-email-detection-distilbert_v2.4.1",
    local_dir="vidic/models/distillbert",
)