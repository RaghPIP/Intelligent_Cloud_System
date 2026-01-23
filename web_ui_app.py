#!/usr/bin/env python3
"""
MODULE 1: NETWORK TRAFFIC CLASSIFIER - WEB UI
Flask web application for viewing classifier results in browser

Author: Final Year Engineering Project
Date: 2026
"""

from flask import Flask, render_template, jsonify
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
import json
import os

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Global variables to store model and data
model = None
X_test = None
y_test = None
y_test_pred = None
le_y = None
metrics = {}
feature_importance = None

def load_and_train_model():
    """Load data and train the model"""
    global model, X_test, y_test, y_test_pred, le_y, metrics, feature_importance
    
    # Load dataset
    df = pd.read_csv('data/NSL-KDD_cleaned.csv')
    
    # Identify and separate label
    label_column = None
    for col in df.columns:
        if col.lower() == 'label':
            label_column = col
            break
    
    X = df.drop(columns=[label_column])
    y = df[label_column]
    
    # Encode features
    for col in X.columns:
        if X[col].dtype == 'object':
            try:
                X[col] = pd.to_numeric(X[col])
            except:
                le = LabelEncoder()
                X[col] = le.fit_transform(X[col].astype(str))
    
    X = X.astype(np.float64)
    
    # Encode labels
    le_y = LabelEncoder()
    y_encoded = le_y.fit_transform(y)
    
    # Remove rare classes
    min_class_size = 10
    class_counts = np.bincount(y_encoded)
    valid_classes = np.where(class_counts >= min_class_size)[0]
    valid_indices = np.isin(y_encoded, valid_classes)
    
    X_filtered = X[valid_indices].reset_index(drop=True)
    y_filtered = y_encoded[valid_indices]
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_filtered, y_filtered,
        test_size=0.2,
        random_state=42,
        stratify=y_filtered
    )
    
    # Train model
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        verbose=0
    )
    model.fit(X_train, y_train)
    
    # Get predictions
    y_test_pred = model.predict(X_test)
    
    # Calculate metrics
    metrics['accuracy'] = float(accuracy_score(y_test, y_test_pred))
    metrics['precision'] = float(precision_score(y_test, y_test_pred, average='weighted', zero_division=0))
    metrics['recall'] = float(recall_score(y_test, y_test_pred, average='weighted', zero_division=0))
    metrics['f1'] = float(f1_score(y_test, y_test_pred, average='weighted', zero_division=0))
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'Feature': X.columns,
        'Importance': model.feature_importances_
    }).sort_values('Importance', ascending=False).head(15)
    
    return le_y, X_test, y_test, y_test_pred

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html', metrics=metrics)

@app.route('/api/metrics')
def get_metrics():
    """API endpoint for metrics"""
    return jsonify(metrics)

@app.route('/api/confusion-matrix')
def get_confusion_matrix():
    """API endpoint for confusion matrix"""
    if y_test is None:
        return jsonify({'error': 'Model not trained'})
    
    cm = confusion_matrix(y_test, y_test_pred, labels=np.unique(y_test))
    
    # Convert to list for JSON serialization
    cm_data = {
        'matrix': cm.tolist(),
        'labels': [str(le_y.classes_[i]) for i in np.unique(y_test)]
    }
    return jsonify(cm_data)

@app.route('/api/feature-importance')
def get_feature_importance():
    """API endpoint for feature importance"""
    if feature_importance is None:
        return jsonify({'error': 'Model not trained'})
    
    data = {
        'features': feature_importance['Feature'].tolist(),
        'importances': feature_importance['Importance'].tolist()
    }
    return jsonify(data)

@app.route('/api/sample-predictions')
def get_sample_predictions():
    """API endpoint for sample predictions"""
    if y_test is None:
        return jsonify({'error': 'Model not trained'})
    
    sample_count = min(5, len(y_test))

    # Ensure at least one normal sample is present when available
    y_labels = np.array([str(le_y.classes_[label]).lower() for label in y_test])
    normal_indices = np.where(y_labels == 'normal')[0]

    chosen_indices = []
    if len(normal_indices) > 0:
        chosen_indices.append(int(np.random.choice(normal_indices)))

    # Fill remaining spots with random distinct samples
    remaining_pool = np.setdiff1d(np.arange(len(y_test)), chosen_indices)
    remaining_needed = sample_count - len(chosen_indices)
    if remaining_needed > 0:
        additional = np.random.choice(
            remaining_pool,
            size=min(remaining_needed, len(remaining_pool)),
            replace=False
        )
        chosen_indices.extend(additional.tolist())

    # Fallback: if we still lack samples (e.g., tiny test set), duplicate the chosen ones
    while len(chosen_indices) < sample_count and len(chosen_indices) > 0:
        chosen_indices.append(chosen_indices[len(chosen_indices) % len(chosen_indices)])

    y_proba = model.predict_proba(X_test)

    predictions = []
    for idx in chosen_indices:
        actual = str(le_y.classes_[y_test[idx]])
        predicted = str(le_y.classes_[y_test_pred[idx]])
        confidence = y_proba[idx][y_test_pred[idx]]
        
        predictions.append({
            'actual': actual,
            'predicted': predicted,
            'confidence': f'{confidence*100:.2f}%'
        })
    
    return jsonify(predictions)

@app.route('/api/dataset-info')
def get_dataset_info():
    """API endpoint for dataset info"""
    return jsonify({
        'total_samples': len(y_test) + len(y_test),  # Approximation
        'test_samples': len(y_test),
        'features': X_test.shape[1],
        'classes': len(np.unique(y_test)),
        'accuracy': f"{metrics['accuracy']*100:.2f}%"
    })

if __name__ == '__main__':
    print("Loading and training model...")
    le_y, X_test, y_test, y_test_pred = load_and_train_model()
    print(f"✓ Model trained! Test Accuracy: {metrics['accuracy']*100:.2f}%")
    port = int(os.environ.get('PORT', '5050'))
    print(f"✓ Starting web server at http://localhost:{port}")
    print(f"✓ Press Ctrl+C to stop")
    app.run(debug=True, port=port, use_reloader=False)
