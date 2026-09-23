"""Train ATLAS's URL phishing classifier from UCI's PhiUSIIL dataset.

The resulting model classifies URL text only. It is not a classifier of an
entire email's maliciousness; email evidence remains explainable and separate.
"""
from __future__ import annotations

import argparse
import shutil
import zipfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import requests
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

PROJECT_DIR = Path(__file__).resolve().parent
UCI_DATASET_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
DATA_DIR = PROJECT_DIR / "data" / "phiusiil"
MODEL_PATH = PROJECT_DIR / "url_model.pkl"


def download_dataset(data_dir: Path) -> Path:
    data_dir.mkdir(parents=True, exist_ok=True)
    csvs = list(data_dir.rglob("*.csv"))
    if csvs:
        return max(csvs, key=lambda path: path.stat().st_size)
    archive_path = data_dir / "phiusiil_phishing_url_dataset.zip"
    print(f"Downloading UCI PhiUSIIL Phishing URL Dataset from {UCI_DATASET_URL}")
    with requests.get(UCI_DATASET_URL, stream=True, timeout=120) as response:
        response.raise_for_status()
        with archive_path.open("wb") as archive:
            shutil.copyfileobj(response.raw, archive)
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(data_dir)
    archive_path.unlink()
    csvs = list(data_dir.rglob("*.csv"))
    if not csvs:
        raise FileNotFoundError("The UCI archive did not contain a CSV file.")
    return max(csvs, key=lambda path: path.stat().st_size)


def find_column(columns, candidates: set[str]) -> str:
    normalized = {str(column).strip().lower(): column for column in columns}
    for candidate in candidates:
        if candidate in normalized:
            return normalized[candidate]
    raise ValueError(f"Could not find one of {sorted(candidates)} in columns: {list(columns)}")


def load_url_labels(csv_path: Path):
    dataframe = pd.read_csv(csv_path, low_memory=False)
    url_column = find_column(dataframe.columns, {"url", "url_text", "urltext"})
    label_column = find_column(dataframe.columns, {"label", "class", "result", "status"})
    urls = dataframe[url_column].fillna("").astype(str).str.strip()
    labels = dataframe[label_column]
    if labels.dtype == object:
        labels = labels.astype(str).str.strip().str.lower().map({"1": 1, "0": 0, "phishing": 1, "legitimate": 0, "benign": 0, "bad": 1, "good": 0})
    labels = pd.to_numeric(labels, errors="coerce")
    valid = urls.ne("") & labels.isin([0, 1])
    urls, labels = urls[valid], labels[valid].astype(int)
    if labels.nunique() != 2:
        raise ValueError("The selected label column does not contain binary phishing labels.")
    print(f"Loaded {len(urls):,} URLs from {csv_path.name} ({int(labels.sum()):,} phishing).")
    return urls, labels


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the ATLAS URL phishing model.")
    parser.add_argument("--dataset", type=Path, help="Optional local PhiUSIIL CSV path.")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--max-samples", type=int, default=60_000,
                        help="Stratified training subset; 0 uses all UCI rows.")
    args = parser.parse_args()
    csv_path = args.dataset if args.dataset else download_dataset(DATA_DIR)
    if not csv_path.is_file():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")
    urls, labels = load_url_labels(csv_path)
    if args.max_samples and len(urls) > args.max_samples:
        urls, _, labels, _ = train_test_split(
            urls, labels, train_size=args.max_samples, random_state=42, stratify=labels
        )
        print(f"Using a stratified {len(urls):,}-URL subset for resource-efficient training.")
    train_urls, test_urls, train_labels, test_labels = train_test_split(urls, labels, test_size=args.test_size, random_state=42, stratify=labels)
    model = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2, max_features=50_000, sublinear_tf=True, dtype=np.float32)),
        # SGD logistic regression scales well to the full UCI dataset and exposes predict_proba.
        ("classifier", SGDClassifier(loss="log_loss", max_iter=100, tol=1e-3, class_weight="balanced", random_state=42)),
    ])
    print("Training character-level TF-IDF + SGD logistic regression URL classifier...")
    model.fit(train_urls, train_labels)
    predictions = model.predict(test_urls)
    probabilities = model.predict_proba(test_urls)[:, list(model.classes_).index(1)]
    print(f"Accuracy:  {accuracy_score(test_labels, predictions):.4f}")
    print(f"Precision: {precision_score(test_labels, predictions, zero_division=0):.4f}")
    print(f"Recall:    {recall_score(test_labels, predictions, zero_division=0):.4f}")
    print(f"F1-score:  {f1_score(test_labels, predictions, zero_division=0):.4f}")
    print(f"ROC-AUC:   {roc_auc_score(test_labels, probabilities):.4f}")
    joblib.dump(model, MODEL_PATH)
    print(f"Saved URL phishing model to {MODEL_PATH}")


if __name__ == "__main__":
    main()
