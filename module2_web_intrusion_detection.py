#!/usr/bin/env python3
"""
MODULE 2: WEB INTRUSION DETECTION SYSTEM (WIDS)
Using Isolation Forest for Anomaly Detection
=========================================================
Detects anomalous web traffic patterns in network flows
Trained on CIC-IDS-2017 dataset
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import sys
from pathlib import Path
from datetime import datetime

def safe_print(*args, **kwargs):
    """Print safely on Windows console with encoding errors"""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, 'encoding', None) or 'utf-8'
        try:
            safe_args = []
            for a in args:
                s = str(a)
                safe_args.append(s.encode(enc, errors='replace').decode(enc))
            sep = kwargs.get('sep', ' ')
            end = kwargs.get('end', '\n')
            file = kwargs.get('file', sys.stdout)
            file.write(sep.join(safe_args) + end)
        except Exception:
            print(*[repr(a) for a in args], **{k: v for k, v in kwargs.items() if k != 'file'})

class WebIntrusionDetectionSystem:
    """Web Intrusion Detection using Isolation Forest"""
    
    def __init__(self, data_file='data/CIC-IDS-2017_cleaned.csv', model_file='models/wids_iforest.pkl'):
        self.data_file = data_file
        self.model_file = model_file
        self.df = None
        self.model = None
        self.scaler = None
        self.features = None
        self.anomaly_predictions = None
        self.stats = {}
        
    def load_data(self):
        """Load and explore CIC-IDS-2017 dataset"""
        safe_print(f"\n{'='*80}")
        safe_print("STEP 1: DATA LOADING AND EXPLORATION")
        safe_print(f"{'='*80}\n")
        
        try:
            safe_print(f"[*] Loading dataset from: {self.data_file}")
            self.df = pd.read_csv(self.data_file)
            safe_print(f"[OK] Dataset loaded successfully\n")
            
            safe_print("1. DATASET OVERVIEW")
            safe_print(f"   Total Records: {len(self.df):,}")
            safe_print(f"   Total Columns: {len(self.df.columns)}")
            safe_print(f"   Memory Usage: {self.df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
            
            safe_print(f"\n2. COLUMN INFORMATION")
            cols_str = ", ".join(list(self.df.columns[:10])) + ("..." if len(self.df.columns) > 10 else "")
            safe_print(f"   Columns: [{cols_str}]")
            
            safe_print(f"\n3. DATA TYPES")
            dtype_counts = self.df.dtypes.value_counts()
            for dtype, count in dtype_counts.items():
                safe_print(f"   {dtype}: {count} columns")
            
            safe_print(f"\n4. LABEL DISTRIBUTION")
            label_cols = [col for col in self.df.columns if 'label' in col.lower() or 'class' in col.lower()]
            if label_cols:
                label_col = label_cols[0]
                label_dist = self.df[label_col].value_counts().head()
                safe_print(label_dist.to_string())
            else:
                safe_print("   [INFO] No label column found")
            
            safe_print(f"\n5. MISSING VALUES")
            missing = self.df.isnull().sum()
            if missing.sum() == 0:
                safe_print(f"   No missing values found - Dataset is clean!")
            else:
                safe_print(f"   Columns with missing values: {len(missing[missing > 0])}")
            
            safe_print(f"\n6. DATA PREVIEW (First 3 rows)")
            preview_cols = list(self.df.columns[:5])
            safe_print(self.df[preview_cols].head(3).to_string())
            
            self.stats['total_records'] = len(self.df)
            return True
            
        except Exception as e:
            safe_print(f"[ERROR] Failed to load dataset: {e}")
            return False
    
    def engineer_web_features(self):
        """Engineer web behavioral features from network flows"""
        safe_print(f"\n{'='*80}")
        safe_print("STEP 2: WEB BEHAVIOR FEATURE ENGINEERING")
        safe_print(f"{'='*80}\n")
        
        try:
            safe_print("[*] Creating web traffic behavioral features...")
            
            # Create windows for behavioral aggregation
            window_size = 100
            self.df['flow_group'] = self.df.index // window_size
            
            # Feature 1: Request count per window
            safe_print(f"   [1/8] Request count per flow group")
            request_count = self.df.groupby('flow_group').size()
            self.df['request_count'] = self.df['flow_group'].map(request_count)
            
            # Feature 2: Unique destination ports
            safe_print(f"   [2/8] Unique destination ports")
            dst_port_col = None
            for col in self.df.columns:
                if 'destination' in col.lower() and 'port' in col.lower():
                    dst_port_col = col
                    break
            
            if dst_port_col:
                unique_ports = self.df.groupby('flow_group')[dst_port_col].nunique()
                self.df['unique_dst_ports'] = self.df['flow_group'].map(unique_ports).fillna(1)
            else:
                self.df['unique_dst_ports'] = 1.0
            
            # Feature 3: Mean bytes sent
            safe_print(f"   [3/8] Mean bytes sent")
            fwd_bytes_col = 'Total Length of Fwd Packets' if 'Total Length of Fwd Packets' in self.df.columns else None
            if fwd_bytes_col:
                mean_sent = self.df.groupby('flow_group')[fwd_bytes_col].mean()
                self.df['mean_bytes_sent'] = self.df['flow_group'].map(mean_sent).fillna(10.0)
            else:
                self.df['mean_bytes_sent'] = 10.0
            
            # Feature 4: Mean bytes received
            safe_print(f"   [4/8] Mean bytes received")
            bwd_col = None
            for col in self.df.columns:
                if 'total' in col.lower() and 'backward' in col.lower() and 'packets' in col.lower():
                    bwd_col = col
                    break
            
            if bwd_col:
                mean_received = self.df.groupby('flow_group')[bwd_col].mean()
                self.df['mean_bytes_received'] = self.df['flow_group'].map(mean_received).fillna(5.0)
            else:
                self.df['mean_bytes_received'] = 5.0
            
            # Feature 5: Request rate (flows per second)
            safe_print(f"   [5/8] Request rate")
            dur_col = None
            for col in self.df.columns:
                if 'flow' in col.lower() and 'duration' in col.lower():
                    dur_col = col
                    break
            
            if dur_col:
                mean_duration = self.df.groupby('flow_group')[dur_col].mean()
                self.df['request_rate'] = self.df['flow_group'].map(request_count) / (self.df['flow_group'].map(mean_duration).fillna(1) + 0.001)
            else:
                self.df['request_rate'] = self.df['request_count'].fillna(1.0)
            
            # Feature 6: Duration statistics
            safe_print(f"   [6/8] Flow duration mean")
            if dur_col:
                duration_mean = self.df.groupby('flow_group')[dur_col].mean()
                self.df['duration_mean'] = self.df['flow_group'].map(duration_mean).fillna(100.0)
            else:
                self.df['duration_mean'] = 100.0
            
            # Feature 7: Packet count mean
            safe_print(f"   [7/8] Packet count mean")
            fwd_pkt_col = None
            for col in self.df.columns:
                if 'total' in col.lower() and 'fwd' in col.lower() and 'packets' in col.lower():
                    fwd_pkt_col = col
                    break
            
            if fwd_pkt_col:
                packet_mean = self.df.groupby('flow_group')[fwd_pkt_col].mean()
                self.df['packet_count_mean'] = self.df['flow_group'].map(packet_mean).fillna(10.0)
            else:
                self.df['packet_count_mean'] = 10.0
            
            # Feature 8: Byte ratio
            safe_print(f"   [8/8] Byte ratio")
            if fwd_bytes_col and bwd_col:
                self.df['byte_ratio'] = (self.df[fwd_bytes_col] + 1) / (self.df[bwd_col] + 1)
            else:
                self.df['byte_ratio'] = 1.0
            
            # Replace infinities and NaNs
            self.df['byte_ratio'] = self.df['byte_ratio'].replace([np.inf, -np.inf], 1.0).fillna(1.0)
            
            safe_print(f"[OK] Feature engineering completed\n")
            return True
            
        except Exception as e:
            safe_print(f"[ERROR] Feature engineering failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def prepare_model_data(self):
        """Prepare features for model training"""
        safe_print(f"{'='*80}")
        safe_print("STEP 3: DATA PREPARATION FOR ANOMALY DETECTION")
        safe_print(f"{'='*80}\n")
        
        try:
            # Select engineered features
            feature_cols = ['request_count', 'unique_dst_ports', 'mean_bytes_sent', 
                          'mean_bytes_received', 'request_rate', 'duration_mean', 
                          'packet_count_mean', 'byte_ratio']
            
            # Check all features exist
            for col in feature_cols:
                if col not in self.df.columns:
                    safe_print(f"[WARNING] Feature {col} not found, using default value")
                    self.df[col] = 1.0
            
            self.features = self.df[feature_cols].copy()
            
            # Replace any infinities
            self.features = self.features.replace([np.inf, -np.inf], np.nan)
            self.features.fillna(self.features.median(), inplace=True)
            
            safe_print(f"[OK] Features selected: {len(feature_cols)}")
            safe_print(f"   Features: {', '.join(feature_cols)}")
            safe_print(f"   Total samples: {len(self.features):,}\n")
            
            # Standardize features
            self.scaler = StandardScaler()
            features_scaled = self.scaler.fit_transform(self.features)
            
            safe_print(f"[OK] Features scaled using StandardScaler")
            safe_print(f"   Mean: {features_scaled.mean():.4f}")
            safe_print(f"   Std: {features_scaled.std():.4f}\n")
            
            return features_scaled
            
        except Exception as e:
            safe_print(f"[ERROR] Data preparation failed: {e}")
            return None
    
    def train_anomaly_detector(self, X_scaled):
        """Train Isolation Forest model"""
        safe_print(f"{'='*80}")
        safe_print("STEP 4: ISOLATION FOREST TRAINING")
        safe_print(f"{'='*80}\n")
        
        try:
            safe_print("[*] Training Isolation Forest model...")
            safe_print("   Parameters:")
            safe_print("      n_estimators: 200")
            safe_print("      contamination: 0.05 (expect 5% anomalies)")
            safe_print("      random_state: 42\n")
            
            self.model = IsolationForest(
                n_estimators=200,
                contamination=0.05,
                random_state=42,
                n_jobs=-1
            )
            
            self.anomaly_predictions = self.model.fit_predict(X_scaled)
            
            # Count anomalies
            n_anomalies = (self.anomaly_predictions == -1).sum()
            n_normal = (self.anomaly_predictions == 1).sum()
            anomaly_pct = (n_anomalies / len(self.anomaly_predictions)) * 100
            
            safe_print(f"[OK] Model training completed")
            safe_print(f"   Normal flows: {n_normal:,} ({100-anomaly_pct:.2f}%)")
            safe_print(f"   Anomalies: {n_anomalies:,} ({anomaly_pct:.2f}%)\n")
            
            self.stats['total_requests'] = len(self.anomaly_predictions)
            self.stats['anomalies_detected'] = n_anomalies
            self.stats['anomaly_percentage'] = anomaly_pct
            
            return True
            
        except Exception as e:
            safe_print(f"[ERROR] Model training failed: {e}")
            return False
    
    def save_model(self):
        """Save trained model"""
        try:
            Path(self.model_file).parent.mkdir(parents=True, exist_ok=True)
            
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'features': ['request_count', 'unique_dst_ports', 'mean_bytes_sent',
                            'mean_bytes_received', 'request_rate', 'duration_mean',
                            'packet_count_mean', 'byte_ratio'],
                'timestamp': datetime.now().isoformat()
            }
            
            with open(self.model_file, 'wb') as f:
                pickle.dump(model_data, f)
            
            safe_print(f"[OK] Model saved to: {self.model_file}\n")
            return True
            
        except Exception as e:
            safe_print(f"[ERROR] Failed to save model: {e}")
            return False
    
    def generate_anomaly_report(self):
        """Generate detailed anomaly report"""
        safe_print(f"{'='*80}")
        safe_print("STEP 5: ANOMALY ANALYSIS AND REPORTING")
        safe_print(f"{'='*80}\n")
        
        try:
            # Add predictions to dataframe
            self.df['anomaly'] = self.anomaly_predictions
            self.df['is_anomaly'] = (self.anomaly_predictions == -1).astype(int)
            
            # Get anomalous records
            anomalies = self.df[self.df['is_anomaly'] == 1]
            
            safe_print(f"1. SUMMARY STATISTICS")
            safe_print(f"   Total Web Requests Analyzed: {len(self.df):,}")
            safe_print(f"   Anomalies Detected: {len(anomalies):,}")
            safe_print(f"   Anomaly Percentage: {(len(anomalies)/len(self.df)*100):.2f}%")
            safe_print(f"   Detection Rate: {(len(anomalies)/len(self.df)*100):.2f}%\n")
            
            safe_print(f"2. ANOMALY DISTRIBUTION")
            safe_print(f"   Normal Flows: {(self.anomaly_predictions == 1).sum():,}")
            safe_print(f"   Anomalous Flows: {(self.anomaly_predictions == -1).sum():,}\n")
            
            safe_print(f"3. TOP ANOMALOUS RECORDS (Sample of 10)")
            if len(anomalies) > 0:
                sample_cols = ['request_count', 'unique_dst_ports', 'mean_bytes_sent', 'byte_ratio']
                sample = anomalies.iloc[:min(10, len(anomalies))][sample_cols]
                safe_print(sample.to_string())
            else:
                safe_print("   No anomalies detected")
            
            safe_print(f"\n4. ALERT TRIGGER")
            alert_threshold = 0.05  # 5%
            anomaly_rate = self.stats['anomaly_percentage'] / 100
            
            if anomaly_rate > alert_threshold:
                safe_print(f"   [ALERT] Anomaly rate ({anomaly_rate*100:.2f}%) exceeds threshold ({alert_threshold*100:.1f}%)")
                safe_print(f"   Action: ESCALATE to security team")
                safe_print(f"   Severity: HIGH\n")
                self.stats['alert_triggered'] = True
            else:
                safe_print(f"   [OK] Anomaly rate ({anomaly_rate*100:.2f}%) below threshold ({alert_threshold*100:.1f}%)")
                safe_print(f"   Status: System normal\n")
                self.stats['alert_triggered'] = False
            
            return True
            
        except Exception as e:
            safe_print(f"[ERROR] Report generation failed: {e}")
            return False
    
    def run_complete_pipeline(self):
        """Execute complete WIDS pipeline"""
        safe_print(f"\n{'='*80}")
        safe_print("MODULE 2: WEB INTRUSION DETECTION SYSTEM (WIDS)")
        safe_print("Using Isolation Forest for Anomaly Detection")
        safe_print(f"{'='*80}")
        
        # Load data
        if not self.load_data():
            return False
        
        # Engineer features
        if not self.engineer_web_features():
            return False
        
        # Prepare model data
        X_scaled = self.prepare_model_data()
        if X_scaled is None:
            return False
        
        # Train model
        if not self.train_anomaly_detector(X_scaled):
            return False
        
        # Save model
        self.save_model()
        
        # Generate report
        if not self.generate_anomaly_report():
            return False
        
        # Final summary
        safe_print(f"{'='*80}")
        safe_print("WIDS EXECUTION SUMMARY")
        safe_print(f"{'='*80}")
        safe_print(f"Total Records Analyzed:     {self.stats['total_requests']:,}")
        safe_print(f"Anomalies Detected:         {self.stats['anomalies_detected']:,}")
        safe_print(f"Anomaly Percentage:         {self.stats['anomaly_percentage']:.2f}%")
        safe_print(f"Alert Triggered:            {'YES' if self.stats['alert_triggered'] else 'NO'}")
        safe_print(f"Model Saved:                {self.model_file}")
        safe_print(f"Timestamp:                  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        safe_print(f"{'='*80}\n")
        
        return True

def main():
    """Main execution function"""
    wids = WebIntrusionDetectionSystem(
        data_file='data/CIC-IDS-2017_cleaned.csv',
        model_file='models/wids_iforest.pkl'
    )
    
    success = wids.run_complete_pipeline()
    return wids if success else None

if __name__ == '__main__':
    wids = main()
    sys.exit(0 if wids else 1)
