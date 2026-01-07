#!/usr/bin/env python3
"""
Phase 1: Data Preprocessing for Intelligent Threat Detection System
===================================================================

This script performs comprehensive data preprocessing for:
1. Network Traffic Classifier (NSL-KDD, UNSW-NB15, CIC-IDS-2017)
2. Web Intrusion Detection System (HTTP Access Logs)
3. Malware Analysis System (Binary Features)

Author: Final Year Engineering Project
Date: 2024
"""

import pandas as pd
import numpy as np
import os
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# Set display options
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', 50)

class DataPreprocessor:
    """Main preprocessing class for all modules"""
    
    def __init__(self, data_dir='data'):
        self.data_dir = Path(data_dir)
        self.results = {}
        self.cleaning_log = []
        self.feature_engineering_log = []
        self.feature_selection_log = []
        
    def inspect_dataset(self, filepath, dataset_name):
        """Inspect dataset and return statistics"""
        print(f"\n{'='*80}")
        print(f"DATASET INSPECTION: {dataset_name}")
        print(f"{'='*80}")
        
        # Load dataset
        try:
            if filepath.suffix == '.parquet':
                df = pd.read_parquet(filepath)
            else:
                # Check if NSL-KDD (no header, numeric column names)
                if 'NSL_KDD' in str(filepath) or 'NSL-KDD' in str(filepath):
                    # Standard KDD Cup 99 feature names (41 features + label)
                    kdd_features = [
                        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
                        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
                        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
                        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
                        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
                        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
                        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
                        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label'
                    ]
                    df = pd.read_csv(filepath, header=None, names=kdd_features, low_memory=False)
                else:
                    df = pd.read_csv(filepath, low_memory=False)
        except Exception as e:
            print(f"Error loading {filepath}: {e}")
            return None
        
        # Basic statistics
        print(f"\n1. BASIC STATISTICS")
        print(f"   Total Rows: {len(df):,}")
        print(f"   Total Columns: {len(df.columns)}")
        print(f"   Memory Usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
        
        # Column information
        print(f"\n2. COLUMN INFORMATION")
        print(f"   Column Names: {list(df.columns)[:10]}..." if len(df.columns) > 10 else f"   Column Names: {list(df.columns)}")
        
        # Missing values
        print(f"\n3. MISSING VALUES ANALYSIS")
        missing = df.isnull().sum()
        missing_pct = (missing / len(df)) * 100
        missing_df = pd.DataFrame({
            'Column': missing.index,
            'Missing Count': missing.values,
            'Missing %': missing_pct.values
        })
        missing_df = missing_df[missing_df['Missing Count'] > 0].sort_values('Missing Count', ascending=False)
        
        if len(missing_df) > 0:
            print(f"   Columns with missing values: {len(missing_df)}")
            print(missing_df.head(10).to_string(index=False))
        else:
            print("   No missing values found!")
        
        # Duplicate records
        print(f"\n4. DUPLICATE RECORDS")
        duplicates = df.duplicated().sum()
        duplicate_pct = (duplicates / len(df)) * 100
        print(f"   Duplicate Rows: {duplicates:,} ({duplicate_pct:.2f}%)")
        
        # Data types
        print(f"\n5. DATA TYPES")
        dtype_counts = df.dtypes.value_counts()
        for dtype, count in dtype_counts.items():
            print(f"   {dtype}: {count} columns")
        
        # Preview data
        print(f"\n6. DATA PREVIEW (First 3 rows)")
        print(df.head(3).to_string())
        
        # Label distribution (if label column exists)
        label_cols = [col for col in df.columns if col.lower() in ['label', 'class', 'attack', 'target']]
        if label_cols:
            print(f"\n7. LABEL DISTRIBUTION")
            label_col = label_cols[0]
            label_dist = df[label_col].value_counts()
            print(f"   Label Column: {label_col}")
            print(label_dist.to_string())
        
        return df
    
    def clean_network_traffic(self, df, dataset_name):
        """Clean network traffic dataset"""
        print(f"\n{'='*80}")
        print(f"DATA CLEANING: {dataset_name}")
        print(f"{'='*80}")
        
        original_rows = len(df)
        original_cols = len(df.columns)
        
        cleaning_actions = []
        
        # 1. Remove duplicates
        duplicates = df.duplicated().sum()
        if duplicates > 0:
            df = df.drop_duplicates()
            cleaning_actions.append({
                'Column': 'All',
                'Issue': f'{duplicates:,} duplicate records',
                'Action': 'Removed duplicate rows',
                'Reason': 'Prevent model bias toward frequent patterns'
            })
        
        # 2. Handle missing values
        missing = df.isnull().sum()
        for col in missing[missing > 0].index:
            missing_count = missing[col]
            missing_pct = (missing_count / len(df)) * 100
            
            if df[col].dtype in ['int64', 'float64']:
                # Numerical: use median
                median_val = df[col].median()
                df[col].fillna(median_val, inplace=True)
                action = f'Filled with median ({median_val:.2f})'
            else:
                # Categorical: use mode
                mode_val = df[col].mode()[0] if len(df[col].mode()) > 0 else 'Unknown'
                df[col].fillna(mode_val, inplace=True)
                action = f'Filled with mode ({mode_val})'
            
            cleaning_actions.append({
                'Column': col,
                'Issue': f'{missing_count:,} missing values ({missing_pct:.2f}%)',
                'Action': action,
                'Reason': 'Preserve data distribution while handling missing data'
            })
        
        # 3. Remove irrelevant/high-cardinality identifier columns
        # Identify potential identifier columns
        identifier_patterns = ['id', 'index', 'timestamp', 'time', 'date']
        identifier_cols = [col for col in df.columns 
                          if any(pattern in col.lower() for pattern in identifier_patterns)]
        
        # Check for high cardinality (potential identifiers)
        high_cardinality = []
        for col in df.columns:
            if df[col].dtype == 'object':
                unique_ratio = df[col].nunique() / len(df)
                if unique_ratio > 0.9:  # More than 90% unique values
                    high_cardinality.append(col)
        
        cols_to_remove = list(set(identifier_cols + high_cardinality))
        # Don't remove if it's the only timestamp or if it's needed for temporal features
        cols_to_remove = [col for col in cols_to_remove 
                         if col.lower() not in ['label', 'class', 'attack', 'target']]
        
        if cols_to_remove:
            df = df.drop(columns=cols_to_remove)
            for col in cols_to_remove:
                cleaning_actions.append({
                    'Column': col,
                    'Issue': 'High cardinality or identifier column',
                    'Action': 'Removed column',
                    'Reason': 'Prevent overfitting; identifiers not useful for prediction'
                })
        
        # 4. Standardize label column
        label_cols = [col for col in df.columns if col.lower() in ['label', 'class', 'attack', 'target']]
        if label_cols:
            label_col = label_cols[0]
            # Standardize to 'Label' column name
            if label_col != 'Label':
                df = df.rename(columns={label_col: 'Label'})
                cleaning_actions.append({
                    'Column': label_col,
                    'Issue': 'Non-standard column name',
                    'Action': f'Renamed to "Label"',
                    'Reason': 'Standardize column naming across datasets'
                })
            
            # Normalize label values (convert to lowercase, remove extra spaces)
            if df['Label'].dtype == 'object':
                df['Label'] = df['Label'].str.strip().str.lower()
        
        # Summary
        print(f"\nCLEANING SUMMARY:")
        print(f"   Original Rows: {original_rows:,}")
        print(f"   Final Rows: {len(df):,}")
        print(f"   Rows Removed: {original_rows - len(df):,}")
        print(f"   Original Columns: {original_cols}")
        print(f"   Final Columns: {len(df.columns)}")
        print(f"   Columns Removed: {original_cols - len(df.columns)}")
        
        # Create cleaning log table
        if cleaning_actions:
            cleaning_df = pd.DataFrame(cleaning_actions)
            print(f"\nCLEANING ACTIONS TABLE:")
            print(cleaning_df.to_string(index=False))
            self.cleaning_log.append({
                'dataset': dataset_name,
                'actions': cleaning_df
            })
        
        return df
    
    def engineer_features_network(self, df, dataset_name):
        """Engineer new features for network traffic"""
        print(f"\n{'='*80}")
        print(f"FEATURE ENGINEERING: {dataset_name}")
        print(f"{'='*80}")
        
        new_features = []
        
        # Statistical features (CIC-IDS-2017 specific)
        if 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
            # Packet ratio
            df['Packet_Ratio'] = df['Total Fwd Packets'] / (df['Total Backward Packets'] + 1)
            new_features.append({
                'Feature': 'Packet_Ratio',
                'Type': 'Statistical',
                'Formula': 'Total Fwd Packets / (Total Backward Packets + 1)',
                'Usefulness': 'Captures communication asymmetry; unidirectional flows indicate attacks'
            })
        
        if 'Total Length of Fwd Packets' in df.columns and 'Total Length of Bwd Packets' in df.columns:
            # Byte ratio
            df['Byte_Ratio'] = df['Total Length of Fwd Packets'] / (df['Total Length of Bwd Packets'] + 1)
            new_features.append({
                'Feature': 'Byte_Ratio',
                'Type': 'Statistical',
                'Formula': 'Total Fwd Bytes / (Total Bwd Bytes + 1)',
                'Usefulness': 'Indicates data transfer direction; attacks often show asymmetric patterns'
            })
        
        if 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
            # Asymmetry score
            total_packets = df['Total Fwd Packets'] + df['Total Backward Packets']
            df['Asymmetry_Score'] = abs(df['Total Fwd Packets'] - df['Total Backward Packets']) / (total_packets + 1)
            new_features.append({
                'Feature': 'Asymmetry_Score',
                'Type': 'Behavioral',
                'Formula': '|Fwd Packets - Bwd Packets| / Total Packets',
                'Usefulness': 'High asymmetry indicates scanning or DDoS attacks'
            })
        
        # Temporal features
        if 'Flow IAT Mean' in df.columns and 'Flow IAT Std' in df.columns:
            # Burstiness (coefficient of variation)
            df['Burstiness'] = df['Flow IAT Std'] / (df['Flow IAT Mean'] + 1e-6)
            new_features.append({
                'Feature': 'Burstiness',
                'Type': 'Temporal',
                'Formula': 'Flow IAT Std / Flow IAT Mean',
                'Usefulness': 'High burstiness indicates attack traffic patterns (port scans, DDoS)'
            })
        
        if 'Flow Duration' in df.columns and 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
            # Flow rate
            total_packets = df['Total Fwd Packets'] + df['Total Backward Packets']
            df['Flow_Rate'] = total_packets / (df['Flow Duration'] + 1)
            new_features.append({
                'Feature': 'Flow_Rate',
                'Type': 'Temporal',
                'Formula': 'Total Packets / Flow Duration',
                'Usefulness': 'High flow rate indicates flooding attacks'
            })
        
        # Packet size features
        if 'Packet Length Mean' in df.columns and 'Packet Length Std' in df.columns:
            # Coefficient of variation
            df['Packet_Size_CV'] = df['Packet Length Std'] / (df['Packet Length Mean'] + 1e-6)
            new_features.append({
                'Feature': 'Packet_Size_CV',
                'Type': 'Statistical',
                'Formula': 'Packet Length Std / Packet Length Mean',
                'Usefulness': 'Size variation patterns distinguish attack types'
            })
        
        # TCP flag features
        flag_cols = [col for col in df.columns if any(flag in col for flag in ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG'])]
        if len(flag_cols) >= 3:
            # Flag combination score
            flag_weights = {'SYN': 1, 'ACK': 2, 'FIN': 4, 'RST': 8, 'PSH': 16, 'URG': 32}
            flag_score = 0
            for flag, weight in flag_weights.items():
                flag_col = [col for col in flag_cols if flag in col]
                if flag_col:
                    flag_score += df[flag_col[0]].fillna(0) * weight
            df['Flag_Combination_Score'] = flag_score
            new_features.append({
                'Feature': 'Flag_Combination_Score',
                'Type': 'Behavioral',
                'Formula': 'Weighted sum of TCP flags',
                'Usefulness': 'Flag patterns indicate connection state and attack types'
            })
        
        # Port features (handle different column names)
        port_cols = [col for col in df.columns if 'port' in col.lower() and ('destination' in col.lower() or 'dport' in col.lower())]
        if not port_cols:
            # Try alternative names
            port_cols = [col for col in df.columns if 'dport' in col.lower() or col.lower() == 'dst_port']
        
        if port_cols:
            port_col = port_cols[0]
            # Well-known port indicator
            df['Well_Known_Port'] = (df[port_col] < 1024).astype(int)
            new_features.append({
                'Feature': 'Well_Known_Port',
                'Type': 'Behavioral',
                'Formula': '1 if port < 1024, else 0',
                'Usefulness': 'Well-known ports targeted more in attacks'
            })
            
            # Ephemeral port indicator
            df['Ephemeral_Port'] = ((df[port_col] >= 49152) & (df[port_col] <= 65535)).astype(int)
            new_features.append({
                'Feature': 'Ephemeral_Port',
                'Type': 'Behavioral',
                'Formula': '1 if port in 49152-65535, else 0',
                'Usefulness': 'Ephemeral ports indicate client-side connections'
            })
        
        # UNSW-NB15 specific features
        if 'spkts' in df.columns and 'dpkts' in df.columns:
            # Packet ratio for UNSW-NB15
            df['Packet_Ratio_UNSW'] = df['spkts'] / (df['dpkts'] + 1)
            new_features.append({
                'Feature': 'Packet_Ratio_UNSW',
                'Type': 'Statistical',
                'Formula': 'spkts / (dpkts + 1)',
                'Usefulness': 'Source to destination packet ratio'
            })
        
        if 'sbytes' in df.columns and 'dbytes' in df.columns:
            # Byte ratio for UNSW-NB15
            df['Byte_Ratio_UNSW'] = df['sbytes'] / (df['dbytes'] + 1)
            new_features.append({
                'Feature': 'Byte_Ratio_UNSW',
                'Type': 'Statistical',
                'Formula': 'sbytes / (dbytes + 1)',
                'Usefulness': 'Source to destination byte ratio'
            })
        
        # NSL-KDD specific features
        if 'src_bytes' in df.columns and 'dst_bytes' in df.columns:
            # Byte ratio for NSL-KDD
            df['Byte_Ratio_NSL'] = df['src_bytes'] / (df['dst_bytes'] + 1)
            new_features.append({
                'Feature': 'Byte_Ratio_NSL',
                'Type': 'Statistical',
                'Formula': 'src_bytes / (dst_bytes + 1)',
                'Usefulness': 'Source to destination byte ratio'
            })
        
        if 'count' in df.columns and 'srv_count' in df.columns:
            # Service count ratio
            df['Service_Count_Ratio'] = df['count'] / (df['srv_count'] + 1)
            new_features.append({
                'Feature': 'Service_Count_Ratio',
                'Type': 'Behavioral',
                'Formula': 'count / (srv_count + 1)',
                'Usefulness': 'Connection to service connection ratio'
            })
        
        print(f"\nNEW FEATURES CREATED: {len(new_features)}")
        if new_features:
            features_df = pd.DataFrame(new_features)
            print(features_df.to_string(index=False))
            self.feature_engineering_log.append({
                'dataset': dataset_name,
                'features': features_df
            })
        
        return df
    
    def select_features_network(self, df, dataset_name):
        """Select features for network traffic with justifications"""
        print(f"\n{'='*80}")
        print(f"FEATURE SELECTION: {dataset_name}")
        print(f"{'='*80}")
        
        # Identify features to exclude
        excluded_features = []
        included_features = []
        
        # High correlation analysis
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        if 'Label' in numeric_cols:
            numeric_cols.remove('Label')
        
        if len(numeric_cols) > 1:
            corr_matrix = df[numeric_cols].corr().abs()
            high_corr_pairs = []
            for i in range(len(corr_matrix.columns)):
                for j in range(i+1, len(corr_matrix.columns)):
                    if corr_matrix.iloc[i, j] > 0.95:
                        high_corr_pairs.append((
                            corr_matrix.columns[i],
                            corr_matrix.columns[j],
                            corr_matrix.iloc[i, j]
                        ))
            
            # Remove one feature from each high-correlation pair
            features_to_remove = set()
            for feat1, feat2, corr_val in high_corr_pairs:
                # Keep the feature with lower variance (less informative)
                var1 = df[feat1].var()
                var2 = df[feat2].var()
                if var1 < var2:
                    features_to_remove.add(feat1)
                else:
                    features_to_remove.add(feat2)
            
            for feat in features_to_remove:
                excluded_features.append({
                    'Feature': feat,
                    'Module': 'Network Traffic',
                    'Status': 'Excluded',
                    'Justification': f'High correlation (>0.95) with other features; redundant information'
                })
                df = df.drop(columns=[feat])
        
        # Low variance features
        for col in numeric_cols:
            if col in df.columns:
                variance = df[col].var()
                if variance < 1e-6:  # Very low variance
                    excluded_features.append({
                        'Feature': col,
                        'Module': 'Network Traffic',
                        'Status': 'Excluded',
                        'Justification': 'Very low variance (< 1e-6); no discriminative power'
                    })
                    df = df.drop(columns=[col])
        
        # Include all remaining features
        remaining_features = [col for col in df.columns if col != 'Label']
        for feat in remaining_features:
            if feat not in [e['Feature'] for e in excluded_features]:
                included_features.append({
                    'Feature': feat,
                    'Module': 'Network Traffic',
                    'Status': 'Included',
                    'Justification': 'Discriminative power, real-time extractable, low correlation with other features'
                })
        
        # Create feature selection table
        all_features = included_features + excluded_features
        selection_df = pd.DataFrame(all_features)
        
        print(f"\nFEATURE SELECTION SUMMARY:")
        print(f"   Total Features: {len(remaining_features) + len([e['Feature'] for e in excluded_features])}")
        print(f"   Included: {len(included_features)}")
        print(f"   Excluded: {len(excluded_features)}")
        
        if len(selection_df) > 0:
            print(f"\nFEATURE SELECTION TABLE:")
            print(selection_df.to_string(index=False))
            self.feature_selection_log.append({
                'dataset': dataset_name,
                'selection': selection_df
            })
        
        return df
    
    def generate_final_structure(self, df, dataset_name):
        """Generate final cleaned dataset structure"""
        print(f"\n{'='*80}")
        print(f"FINAL DATASET STRUCTURE: {dataset_name}")
        print(f"{'='*80}")
        
        print(f"\n1. DATASET STATISTICS")
        print(f"   Total Rows: {len(df):,}")
        print(f"   Total Columns: {len(df.columns)}")
        print(f"   Feature Columns: {len(df.columns) - (1 if 'Label' in df.columns else 0)}")
        
        print(f"\n2. FEATURE CATEGORIES")
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
        
        if 'Label' in numeric_cols:
            numeric_cols.remove('Label')
        if 'Label' in categorical_cols:
            categorical_cols.remove('Label')
        
        print(f"   Numeric Features: {len(numeric_cols)}")
        print(f"   Categorical Features: {len(categorical_cols)}")
        
        print(f"\n3. TARGET LABEL FORMAT")
        if 'Label' in df.columns:
            label_dist = df['Label'].value_counts()
            print(f"   Label Column: Label")
            print(f"   Unique Labels: {df['Label'].nunique()}")
            print(f"   Label Distribution:")
            print(label_dist.to_string())
        
        print(f"\n4. FINAL DATASET PREVIEW (First 5 rows)")
        preview_cols = list(df.columns[:10]) + (['Label'] if 'Label' in df.columns else [])
        print(df[preview_cols].head(5).to_string())
        
        return {
            'rows': len(df),
            'columns': len(df.columns),
            'numeric_features': len(numeric_cols),
            'categorical_features': len(categorical_cols),
            'label_distribution': df['Label'].value_counts().to_dict() if 'Label' in df.columns else {}
        }

def main():
    """Main execution function"""
    print("="*80)
    print("PHASE 1: DATA PREPROCESSING")
    print("Intelligent Threat Detection and Response for Cloud Platforms")
    print("="*80)
    
    preprocessor = DataPreprocessor(data_dir='data')
    
    # Process Network Traffic datasets
    # First try predefined names, then scan for any CSV files
    network_datasets = {}
    
    # Scan for all CSV files in data folder (for uploaded files)
    data_dir = Path('data')
    csv_files = list(data_dir.glob('*.csv'))
    
    # Filter out already processed files and cleaned files
    csv_files = [f for f in csv_files if '_cleaned' not in f.name and '-cleaned' not in f.name]
    
    print(f"\nFound {len(csv_files)} CSV file(s) to process: {[f.name for f in csv_files]}")
    
    # Add all CSV files found
    for csv_file in csv_files:
        file_stem = csv_file.stem
        # Use filename as dataset name (clean it up)
        dataset_name = file_stem.replace('_', '-').replace(' ', '-')
        # Remove common suffixes
        for suffix in ['_cleaned', '-cleaned', '_clean', '-clean']:
            if dataset_name.endswith(suffix):
                dataset_name = dataset_name[:-len(suffix)]
        network_datasets[dataset_name] = str(csv_file)
    
    if not network_datasets:
        print("\nNo CSV files found in data/ folder. Please upload datasets first.")
        return preprocessor, {}
    
    processed_datasets = {}
    
    for name, filepath in network_datasets.items():
        filepath = Path(filepath)
        if not filepath.exists():
            print(f"\nWarning: {filepath} not found. Skipping {name}.")
            continue
        
        # 1. Inspection
        df = preprocessor.inspect_dataset(filepath, name)
        if df is None:
            continue
        
        # 2. Cleaning
        df_cleaned = preprocessor.clean_network_traffic(df.copy(), name)
        
        # 3. Feature Engineering
        df_engineered = preprocessor.engineer_features_network(df_cleaned.copy(), name)
        
        # 4. Feature Selection
        df_final = preprocessor.select_features_network(df_engineered.copy(), name)
        
        # 5. Final Structure
        structure = preprocessor.generate_final_structure(df_final, name)
        processed_datasets[name] = {
            'dataframe': df_final,
            'structure': structure
        }
        
        # Save cleaned dataset
        output_path = f'data/{name}_cleaned.csv'
        df_final.to_csv(output_path, index=False)
        print(f"\n✓ Cleaned dataset saved to: {output_path}")
    
    # Generate summary report
    print(f"\n{'='*80}")
    print("PHASE 1 SUMMARY")
    print(f"{'='*80}")
    
    print("\nPreprocessing completed for Network Traffic datasets.")
    print("Web Logs and Malware datasets will be processed when available.")
    
    return preprocessor, processed_datasets

if __name__ == '__main__':
    preprocessor, datasets = main()

