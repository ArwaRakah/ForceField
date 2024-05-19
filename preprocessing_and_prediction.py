import logging
import os

import pandas as pd
import numpy as np
from joblib import load

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Load model and scaler functions
def load_model(model_path):
    model = load(model_path)
    logging.info("Model loaded successfully")
    return model


def load_scaler(scaler_path):
    scaler = load(scaler_path)
    logging.info("Scaler loaded successfully")
    return scaler


# Preprocess data functions
def load_dataset(filepath):
    dataframes = []
    for path in filepath:
        try:
            df = pd.read_csv(path)
            dataframes.append(df)
        except FileNotFoundError:
            logging.warning(f"{path} does not exist and will be skipped.")
    return pd.concat(dataframes, ignore_index=True)


def clean_data(df):
    logging.info("In clean_data")
    df.drop(['Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Timestamp','Label',
             'Active Std', 'Bwd PSH Flags', 'Subflow Bwd Packets'], axis=1, inplace=True)
    df.drop_duplicates(inplace=True)
    return df


def remove_single_value_columns(df):
    logging.info("In remove_single_value_columns")
    exclude_columns = [
        'Bwd Bulk Rate Avg',
        'Bwd Bytes/Bulk Avg',
        'Bwd Packet/Bulk Avg',
        'FWD Init Win Bytes',
        'Fwd PSH Flags',
        'Fwd Seg Size Min',
        'Fwd URG Flags',
        'URG Flag Count',
        'CWR Flag Count',
        'ECE Flag Count'
    ]
    single_value_columns = set(df.columns[df.nunique() == 1])
    columns_to_drop = single_value_columns - set(exclude_columns)
    df.drop(columns=columns_to_drop, inplace=True)
    return df


def handle_outliers(df):
    logging.info("In handle_outliers")
    # outliers handling
    numerical_cols = df.select_dtypes(include=[np.number]).columns
    for col in numerical_cols:
        min_val = df[col].min()
        if (min_val <= 0):
            df[col] = df[col] + abs(min_val) + 0.0001  # Shift the data to positive domain
            # Applying log transformation to reduce skewness and impact of outliers
        df[col] = np.log1p(df[col])
    return df


def check_data(X):
    logging.info("In check_data")
    # Check and replace NaN values in the DataFrame
    if X.isna().any().any():
        logging.info("NaN values found in the dataset.")
        X.fillna(0, inplace=True)
    numeric_cols = X.select_dtypes(include=[np.number])
    if np.isinf(numeric_cols).any().any():
        logging.info("Infinite values found in the dataset.")
        X[numeric_cols.columns] = numeric_cols.replace([np.inf, -np.inf], np.finfo(np.float64).max)


def preprocess_data(filepath):
    df = load_dataset(filepath)
    df = clean_data(df)
    check_data(df)
    df = remove_single_value_columns(df)
    check_data(df)
    df = handle_outliers(df)
    check_data(df)
    return df


def make_predictions(model, scaler, X):
    X_scaled = scaler.transform(X)
    predictions = model.predict(X_scaled)
    prediction_probs = model.predict_proba(X_scaled)  # Get probabilities

    class_mapping = {0: "Stage 5 - Data Exfiltration", 1: "Stage 2 - Initial Compromise",
                     2: "Stage 3 - Lateral Movement", 3: "Stage 0 - Normal Traffic",
                     4: "Stage 4 - Pivoting", 5: "Stage 1 - Reconnaissance"}

    class_confidences = {class_name: [] for class_name in class_mapping.values()}

    for i, pred in enumerate(predictions):
        if pred == 3:  # Skip prediction for normal traffic
            continue
        class_name = class_mapping.get(pred, "Unknown Stage")
        confidence_score = np.max(prediction_probs[i])
        class_confidences[class_name].append(confidence_score)

    average_confidences = {class_name: np.mean(confidences) if confidences else 0
                           for class_name, confidences in class_confidences.items()}

    detailed_predictions = [f"{class_name} (Average Confidence: {confidence:.2f})"
                            for class_name, confidence in average_confidences.items() if confidence > 0]

    return detailed_predictions


