#!/usr/bin/env python3
"""

Run this in VS Code (Run). It will ask you for:
  • Dataset path
  • Whether to train new models or apply an existing one
  • (If training) whether to use a 70/30 split or train on all data
  • (If testing) which saved model to load
"""

import os
from pathlib import Path
import math
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, classification_report

def calculate_entropy(row):
    values = row.values
    total = sum(values)
    if total == 0:
        return 0
    entropy = 0
    for v in values:
        if v > 0:
            p = v / total
            entropy -= p * math.log2(p)
    return entropy


def build_pipeline(cat_cols, model):
    pre = ColumnTransformer(
        [("cat", OneHotEncoder(handle_unknown="ignore"), cat_cols)],
        remainder="passthrough",
    )
    return Pipeline([("pre", pre), ("clf", model)])


def evaluate(name, pipe, X, y):
    preds = pipe.predict(X)
    print(f"\n── {name} ──")
    print(classification_report(y, preds, digits=3))
    print(f"Accuracy: {accuracy_score(y, preds):.4f}   F1-score: {f1_score(y, preds):.4f}")


def train_firewalls(csv_path: str, fulltrain: bool):
    df = pd.read_csv(csv_path)

    # Calculate entropy and add it as a new feature
    entropy_cols = ["TotPkts", "TotBytes", "SrcPkts", "DstPkts", "SrcBytes"]
    df["entropy"] = df[entropy_cols].apply(calculate_entropy, axis=1)

    y = df["class"]


    # ── Advanced firewall (all features except label) ──
    adv_cols = [c for c in df.columns if c != "class"]
    Xa = df[adv_cols]
    cat_adv = [c for c in ("service", "flag", "protocol_type") if c in Xa]

    adv_fw = build_pipeline(
        cat_adv,
        RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    )

    if fulltrain:
        adv_fw.fit(Xa, y)
    else:
        Xa_tr, Xa_te, ya_tr, ya_te = train_test_split(
            Xa, y, test_size=0.3, stratify=y, random_state=1337
        )

        #simple_fw.fit(Xs_tr, ys_tr)
        adv_fw.fit(Xa_tr, ya_tr)

        evaluate("HOST_IDS", adv_fw, Xa_te, ya_te)

    joblib.dump(adv_fw, "HostIDS.joblib")
    print("\nSaved models: HostIDS.joblib")

def run_firewall(model_path: str, csv_path: str):
    pipe = joblib.load(model_path)
    df = pd.read_csv(csv_path)

    # ➡️ Calculate entropy the same way as during training
    entropy_cols = ["TotPkts", "TotBytes", "SrcPkts", "DstPkts", "SrcBytes"]
    df["entropy"] = df[entropy_cols].apply(calculate_entropy, axis=1)

    feat_cols = pipe.named_steps["pre"].feature_names_in_

    df["prediction"] = pipe.predict(df[list(feat_cols)])

    # If true labels are present, print metrics
    if "class" in df.columns:
        print("\n—— Test-set metrics ——")
        print(classification_report(df["class"], df["prediction"], digits=4))
        print(f"Accuracy: {accuracy_score(df['class'], df['prediction']):.4f}   "
              f"F1-score: {f1_score(df['class'], df['prediction']):.4f}")

    out = Path(csv_path).with_suffix(".pred.csv")
    df.to_csv(out, index=False)
    print(f"Predictions written to {out}")


def main():
    print("\nIDS Firewall Interactive\n")

    # ask for dataset
    dataset = input("Enter path to dataset CSV: ").strip()
    if not dataset:
        dataset = "/Users/bananabros99/Desktop/simple_dataset3.csv"
    while not Path(dataset).is_file():
        dataset = input("File not found. Please enter a valid CSV path: ").strip()

    # choose action
    action = input("\nType 'train' to build new firewalls or 'test' to apply a saved model: ").strip().lower()
    if action == "train":
        ft = input("Train on all data (no hold-out)? (y/N): ").strip().lower() == "y"
        train_firewalls(dataset, fulltrain=ft)

    elif action == "test":
        model = input("Enter model filename: HostIDS.joblib? ").strip()
        while not Path(model).is_file():
            model = input("Model file not found. Enter a valid .joblib path: ").strip()
        run_firewall(model, dataset)

    else:
        print("Invalid choice. Exiting.")


if __name__ == "__main__":
    main()
