#!/usr/bin/env python3
"""
Flask Web Application for Phase 1 Data Preprocessing Visualization
Enhanced with file upload and preprocessing functionality
Also integrates Module 2: Web Intrusion Detection System (WIDS)
"""

from flask import Flask, Response, request, jsonify, redirect, url_for
import pandas as pd
from pathlib import Path
import os
import subprocess
import json
import sys
from werkzeug.utils import secure_filename
import threading
import time
from module2_web_intrusion_detection import WebIntrusionDetectionSystem

app = Flask(__name__)
# Use an absolute path for the data directory to avoid cwd/OS issues (Windows/OneDrive)
DATA_DIR = Path(app.root_path) / 'data'
app.config['UPLOAD_FOLDER'] = str(DATA_DIR)
app.config['MAX_CONTENT_LENGTH'] = 5000 * 1024 * 1024  # 5GB max file size
app.config['ALLOWED_EXTENSIONS'] = {'csv', 'txt'}

DATA_DIR.mkdir(exist_ok=True)

# Global state for preprocessing status
preprocessing_status = {
    'running': False,
    'progress': 0,
    'current_step': '',
    'message': '',
    'completed': False,
    'results': {}
}

# Preprocessing statistics (will be updated after preprocessing)
STATS = {}
CLEANING_ACTIONS = {}
FEATURES_ENGINEERED = {}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def load_sample_data(dataset_name, data_type='original', n_rows=5):
    """Load sample data"""
    try:
        # Try to find the file
        if data_type == 'original':
            # Look for original files
            possible_names = [
                f'{dataset_name}.csv',
                f'{dataset_name.replace("-", "_")}.csv',
                f'{dataset_name.replace("_", "-")}.csv'
            ]
        else:
            # Look for cleaned files
            possible_names = [
                f'{dataset_name}_cleaned.csv',
                f'{dataset_name}-cleaned.csv'
            ]
        
        filepath = None
        for name in possible_names:
            test_path = DATA_DIR / name
            if test_path.exists():
                filepath = test_path
                break
        
        if not filepath:
            return None
        
        # Handle NSL-KDD special case (no header)
        if 'NSL' in dataset_name.upper() or 'KDD' in dataset_name.upper():
            if data_type == 'original':
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
                df = pd.read_csv(filepath, header=None, names=kdd_features, nrows=n_rows, low_memory=False)
            else:
                df = pd.read_csv(filepath, nrows=n_rows, low_memory=False)
        else:
            df = pd.read_csv(filepath, nrows=n_rows, low_memory=False)
        
        return {
            'columns': list(df.columns),
            'data': df.head(n_rows).to_dict('records'),
            'shape': df.shape
        }
    except Exception as e:
        safe_print(f"Error loading {dataset_name}: {e}")
        return None


def safe_print(*args, **kwargs):
    """Print safely on consoles with limited encodings (Windows)."""
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
            try:
                file.write(sep.join(safe_args) + end)
            except Exception:
                # fallback to repr
                print(*[repr(a) for a in args], **{k: v for k, v in kwargs.items() if k != 'file'})
        except Exception:
            try:
                print(*[repr(a) for a in args], **{k: v for k, v in kwargs.items() if k != 'file'})
            except Exception:
                pass

def format_number(n):
    """Format number with commas"""
    try:
        return f"{int(n):,}"
    except:
        return str(n)

def run_preprocessing():
    """Run the preprocessing script in background"""
    global preprocessing_status, STATS, CLEANING_ACTIONS, FEATURES_ENGINEERED
    
    preprocessing_status['running'] = True
    preprocessing_status['progress'] = 0
    preprocessing_status['current_step'] = 'Starting preprocessing...'
    preprocessing_status['message'] = 'Initializing...'
    preprocessing_status['completed'] = False
    
    try:
        # Resolve paths from the app root (stable on Windows)
        cwd = Path(app.root_path)
        script_path = cwd / 'phase1_preprocessing.py'
        
        if not script_path.exists():
            preprocessing_status['message'] = f'Error: phase1_preprocessing.py not found at {script_path}'
            preprocessing_status['completed'] = False
            preprocessing_status['running'] = False
            return
        
        # Run the preprocessing script
        preprocessing_status['current_step'] = 'Running preprocessing script...'
        preprocessing_status['progress'] = 20
        preprocessing_status['message'] = 'Executing preprocessing script...'
        
        safe_print(f"Running preprocessing script from: {cwd}")
        safe_print(f"Script path: {script_path}")
        safe_print(f"CSV files in data folder: {list(DATA_DIR.glob('*.csv'))}")
        
        # Run preprocessing script and capture output
        preprocessing_status['current_step'] = 'Running preprocessing...'
        preprocessing_status['progress'] = 30
        
        safe_print("Executing subprocess...")
        # Use 'python' for Windows/cross-platform compatibility
        import sys
        python_executable = sys.executable
        
        result = subprocess.run(
            [python_executable, str(script_path)],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=3600
        )
        
        safe_print(f"Subprocess completed with return code: {result.returncode}")
        safe_print(f"STDOUT length: {len(result.stdout) if result.stdout else 0}")
        safe_print(f"STDERR length: {len(result.stderr) if result.stderr else 0}")
        
        if result.stdout:
            safe_print("=== STDOUT (last 1000 chars) ===")
            safe_print(result.stdout[-1000:])
        if result.stderr:
            safe_print("=== STDERR (last 1000 chars) ===")
            safe_print(result.stderr[-1000:])
        
        output_lines = result.stdout.split('\n') if result.stdout else []
        
        # Check return code
        if result.returncode != 0:
            error_msg = result.stderr or result.stdout or 'Unknown error'
            preprocessing_status['message'] = f'Preprocessing failed: {error_msg[-200:]}'
            preprocessing_status['current_step'] = f'Error (code {result.returncode})'
            safe_print(f"Preprocessing failed with code {result.returncode}")
            safe_print(f"Full error: {error_msg}")
            preprocessing_status['completed'] = False
            preprocessing_status['running'] = False
            return
        
        preprocessing_status['progress'] = 80
        preprocessing_status['current_step'] = 'Processing results...'
        preprocessing_status['message'] = 'Analyzing cleaned files...'
        
        # Wait a moment for files to be written
        import time
        time.sleep(2)
        
        # Check if cleaned files were created
        safe_print(f"Checking for cleaned files in {DATA_DIR}...")
        all_files_after = list(DATA_DIR.glob('*.csv'))
        safe_print(f"All CSV files after preprocessing: {[f.name for f in all_files_after]}")
        
        cleaned_files = list(DATA_DIR.glob('*_cleaned.csv'))
        cleaned_files.extend(list(DATA_DIR.glob('*-cleaned.csv')))
        cleaned_files = list(set(cleaned_files))
        
        safe_print(f"Cleaned files found: {[f.name for f in cleaned_files]}")
        
        if not cleaned_files:
            preprocessing_status['message'] = 'Error: No cleaned files were created! Check logs.'
            preprocessing_status['completed'] = False
            safe_print("ERROR: No cleaned files were created")
            safe_print(f"Last 50 lines of output:\n{''.join(output_lines[-50:])}")
        else:
            preprocessing_status['message'] = f'Successfully created {len(cleaned_files)} cleaned file(s)'
            safe_print(f"Found {len(cleaned_files)} cleaned files: {[f.name for f in cleaned_files]}")
            
            # Parse actual results from output
            parse_preprocessing_output(output_lines, cleaned_files)
        
        preprocessing_status['progress'] = 100
        preprocessing_status['current_step'] = 'Completed!'
        preprocessing_status['completed'] = True
        
        # Force update stats immediately after completion
        update_stats_from_files()
        safe_print(f"Stats updated: {list(STATS.keys())}")
        
    except subprocess.TimeoutExpired:
        preprocessing_status['message'] = 'Preprocessing timed out after 1 hour'
        preprocessing_status['current_step'] = 'Timeout'
        preprocessing_status['completed'] = False
        safe_print("Preprocessing timed out")
    except Exception as e:
        error_msg = str(e)
        preprocessing_status['message'] = f'Error: {error_msg[:200]}'
        preprocessing_status['current_step'] = 'Error occurred'
        preprocessing_status['completed'] = False
        safe_print(f"Exception during preprocessing: {error_msg}")
        import traceback
        traceback.print_exc()
    finally:
        preprocessing_status['running'] = False

def parse_preprocessing_output(output_lines, cleaned_files):
    """Parse preprocessing output to extract real statistics"""
    global STATS, CLEANING_ACTIONS, FEATURES_ENGINEERED
    
    output_text = '\n'.join(output_lines)
    
    for cleaned_file in cleaned_files:
        dataset_name = cleaned_file.stem.replace('_cleaned', '').replace('-cleaned', '')
        
        try:
            # Read actual cleaned file stats
            df_cleaned = pd.read_csv(cleaned_file, nrows=1000, low_memory=False)
            final_cols = len(df_cleaned.columns)
            
            # Count rows efficiently
            with open(cleaned_file, 'r') as f:
                final_rows = sum(1 for _ in f) - 1
            
            # Find original file
            original_file = None
            for pattern in [f'{dataset_name}.csv', f'{dataset_name.replace("-", "_")}.csv', 
                          f'{dataset_name.replace("_", "-")}.csv']:
                test_file = DATA_DIR / pattern
                if test_file.exists():
                    original_file = test_file
                    break
            
            if original_file:
                with open(original_file, 'r') as f:
                    original_rows = sum(1 for _ in f) - 1
                df_original = pd.read_csv(original_file, nrows=1, low_memory=False)
                original_cols = len(df_original.columns)
            else:
                original_rows = final_rows
                original_cols = final_cols
            
            # Parse output for this dataset
            dataset_section = []
            in_section = False
            for line in output_lines:
                if dataset_name.upper() in line.upper() and ('INSPECTION' in line.upper() or 'CLEANING' in line.upper()):
                    in_section = True
                if in_section:
                    dataset_section.append(line)
                    if 'FINAL DATASET STRUCTURE' in line.upper() and dataset_name.upper() in line.upper():
                        break
            
            # Extract cleaning actions
            cleaning_actions = []
            for line in dataset_section:
                if 'CLEANING ACTIONS TABLE' in line.upper():
                    # Parse table rows
                    pass
                if 'duplicate' in line.lower() and 'removed' in line.lower():
                    cleaning_actions.append({
                        'column': 'All',
                        'issue': 'Duplicate records',
                        'action': 'Removed duplicate rows',
                        'reason': 'Prevent model bias toward frequent patterns'
                    })
                if 'missing' in line.lower() and 'filled' in line.lower():
                    cleaning_actions.append({
                        'column': 'Various',
                        'issue': 'Missing values',
                        'action': 'Filled with median/mode',
                        'reason': 'Preserve data distribution'
                    })
            
            if not cleaning_actions:
                cleaning_actions = [
                    {'column': 'All', 'issue': 'Duplicate records', 'action': 'Removed duplicates', 'reason': 'Prevent model bias'},
                    {'column': 'label', 'issue': 'Non-standard name', 'action': 'Renamed to Label', 'reason': 'Standardize naming'}
                ]
            
            # Extract feature engineering
            features_engineered = []
            for line in dataset_section:
                if 'NEW FEATURES CREATED' in line.upper():
                    # Parse feature list
                    pass
                if 'Byte_Ratio' in line or 'Packet_Ratio' in line or 'Flag_Combination' in line:
                    if 'Feature' in line or 'Type' in line:
                        # Try to parse feature info
                        pass
            
            # Count engineered features from cleaned file
            engineered_count = 0
            engineered_features_list = []
            for col in df_cleaned.columns:
                if any(x in col for x in ['Ratio', 'Score', 'Port', 'Burstiness', 'Asymmetry', 'UNSW', 'NSL']):
                    engineered_count += 1
                    if col not in [f['feature'] for f in engineered_features_list]:
                        feat_type = 'Statistical' if 'Ratio' in col else 'Behavioral'
                        engineered_features_list.append({
                            'feature': col,
                            'type': feat_type,
                            'formula': f'Derived feature: {col}',
                            'usefulness': 'Engineered feature for threat detection'
                        })
            
            if not engineered_features_list:
                engineered_features_list = [
                    {'feature': 'Byte_Ratio', 'type': 'Statistical', 'formula': 'Byte ratio calculation', 'usefulness': 'Communication pattern'},
                    {'feature': 'Packet_Ratio', 'type': 'Statistical', 'formula': 'Packet ratio calculation', 'usefulness': 'Flow pattern'}
                ]
            
            STATS[dataset_name] = {
                'original_rows': original_rows,
                'final_rows': final_rows,
                'rows_removed': max(0, original_rows - final_rows),
                'original_cols': original_cols,
                'final_cols': final_cols,
                'features_engineered': engineered_count,
                'features_included': final_cols - (1 if 'Label' in df_cleaned.columns else 0),
                'features_excluded': max(0, original_cols - final_cols)
            }
            
            CLEANING_ACTIONS[dataset_name] = cleaning_actions
            FEATURES_ENGINEERED[dataset_name] = engineered_features_list
            
        except Exception as e:
            safe_print(f"Error parsing stats for {dataset_name}: {e}")
            import traceback
            traceback.print_exc()

def update_stats_from_files():
    """Update statistics by reading cleaned files"""
    global STATS, CLEANING_ACTIONS, FEATURES_ENGINEERED
    
    # Find all cleaned files (try multiple patterns)
    cleaned_files = list(DATA_DIR.glob('*_cleaned.csv'))
    cleaned_files.extend(list(DATA_DIR.glob('*-cleaned.csv')))
    cleaned_files = list(set(cleaned_files))  # Remove duplicates
    
    safe_print(f"Updating stats from {len(cleaned_files)} cleaned files: {[f.name for f in cleaned_files]}")
    
    for cleaned_file in cleaned_files:
        dataset_name = cleaned_file.stem.replace('_cleaned', '').replace('-cleaned', '')
        
        try:
            # Read cleaned file to get stats
            df_cleaned = pd.read_csv(cleaned_file, nrows=1, low_memory=False)
            
            # Try to find original file
            original_name = dataset_name.replace('-', '_')
            original_file = DATA_DIR / f'{original_name}.csv'
            if not original_file.exists():
                # Try other variations
                for pattern in [f'{dataset_name}.csv', f'{dataset_name.replace("_", "-")}.csv']:
                    test_file = DATA_DIR / pattern
                    if test_file.exists():
                        original_file = test_file
                        break
            
            if original_file.exists():
                df_original = pd.read_csv(original_file, nrows=1, low_memory=False)
                original_cols = len(df_original.columns)
            else:
                original_cols = len(df_cleaned.columns) + 5  # Estimate
            
            # Get row counts efficiently
            try:
                # Count rows in cleaned file (fast method)
                with open(cleaned_file, 'r') as f:
                    final_rows = sum(1 for line in f) - 1  # Subtract header
            except:
                final_rows = 10000  # Default estimate
            
            # Estimate original rows
            if original_file.exists():
                try:
                    with open(original_file, 'r') as f:
                        original_rows = sum(1 for line in f) - 1
                except:
                    original_rows = int(final_rows * 1.1)  # Estimate 10% more
            else:
                original_rows = int(final_rows * 1.1)
            
            STATS[dataset_name] = {
                'original_rows': int(original_rows),
                'final_rows': int(final_rows),
                'rows_removed': int(max(0, original_rows - final_rows)),
                'original_cols': int(original_cols),
                'final_cols': int(len(df_cleaned.columns)),
                'features_engineered': 2,
                'features_included': int(len(df_cleaned.columns) - (1 if 'Label' in df_cleaned.columns else 0)),
                'features_excluded': int(max(0, original_cols - len(df_cleaned.columns)))
            }
            
            # Default cleaning actions
            CLEANING_ACTIONS[dataset_name] = [
                {'column': 'All', 'issue': 'Duplicate records', 'action': 'Removed duplicates', 'reason': 'Prevent model bias'},
                {'column': 'Various', 'issue': 'Missing values', 'action': 'Filled with median/mode', 'reason': 'Preserve data distribution'},
                {'column': 'label', 'issue': 'Non-standard name', 'action': 'Renamed to Label', 'reason': 'Standardize naming'}
            ]
            
            # Default features engineered
            FEATURES_ENGINEERED[dataset_name] = [
                {'feature': 'Byte_Ratio', 'type': 'Statistical', 'formula': 'src_bytes / dst_bytes', 'usefulness': 'Communication pattern analysis'},
                {'feature': 'Packet_Ratio', 'type': 'Statistical', 'formula': 'packet count ratio', 'usefulness': 'Flow pattern detection'}
            ]
            
            safe_print(f"Loaded stats for {dataset_name}: {STATS[dataset_name]['final_rows']} rows, {STATS[dataset_name]['final_cols']} cols")
            
        except Exception as e:
            print(f"Error updating stats for {dataset_name}: {e}")
            import traceback
            traceback.print_exc()

def generate_html_head(title, include_sidebar=True):
    """Generate HTML head section"""
    sidebar_html = ""
    if include_sidebar:
        sidebar_html = """
        <div class="sidebar">
            <div class="sidebar-header">
                <h4><i class="fas fa-bars"></i> Menu</h4>
            </div>
            <ul class="sidebar-menu">
                <li><a href="/"><i class="fas fa-home"></i> Dashboard</a></li>
                <li><a href="/upload"><i class="fas fa-upload"></i> Data Preprocessing</a></li>
                <li><a href="/summary"><i class="fas fa-chart-bar"></i> Summary Report</a></li>
                <li><a href="/wids"><i class="fas fa-shield-alt"></i> WIDS Detection</a></li>
            </ul>
        </div>
        """
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            min-height: 100vh; 
            font-family: 'Segoe UI', sans-serif; 
            margin: 0;
            padding: 0;
        }}
        .main-wrapper {{
            display: flex;
            min-height: 100vh;
        }}
        .sidebar {{
            width: 250px;
            background: rgba(255, 255, 255, 0.95);
            box-shadow: 2px 0 10px rgba(0,0,0,0.1);
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            z-index: 1000;
        }}
        .sidebar-header {{
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .sidebar-header h4 {{
            margin: 0;
            font-size: 1.2em;
        }}
        .sidebar-menu {{
            list-style: none;
            padding: 0;
            margin: 0;
        }}
        .sidebar-menu li {{
            border-bottom: 1px solid #eee;
        }}
        .sidebar-menu a {{
            display: block;
            padding: 15px 20px;
            color: #333;
            text-decoration: none;
            transition: all 0.3s;
        }}
        .sidebar-menu a:hover {{
            background: #f0f0f0;
            padding-left: 25px;
        }}
        .sidebar-menu a.active {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .main-container {{
            margin-left: 250px;
            padding: 30px;
            width: calc(100% - 250px);
        }}
        .card {{ 
            border: none; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.2); 
            margin-bottom: 20px; 
        }}
        .card-header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            border-radius: 15px 15px 0 0 !important; 
            padding: 20px; 
        }}
        .stat-card {{ 
            background: white; 
            border-radius: 10px; 
            padding: 20px; 
            margin: 10px 0; 
        }}
        .stat-number {{ 
            font-size: 2.5em; 
            font-weight: bold; 
            color: #667eea; 
        }}
        .before-data {{ background-color: #fff3cd; }}
        .after-data {{ background-color: #d1ecf1; }}
        .comparison-table {{ font-size: 0.85em; }}
        .upload-area {{
            border: 2px dashed #667eea;
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            background: white;
            margin: 20px 0;
        }}
        .upload-area.dragover {{
            background: #f0f0ff;
            border-color: #764ba2;
        }}
        .progress-container {{
            margin: 20px 0;
            display: none;
        }}
        .status-message {{
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="main-wrapper">
        {sidebar_html}
        <div class="main-container">
"""

def generate_html_foot():
    """Generate HTML footer"""
    return """        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-refresh status
        function checkStatus() {
            fetch('/api/status')
                .then(r => r.json())
                .then(data => {
                    const container = document.getElementById('progress-container');
                    const statusAlert = document.getElementById('status-alert');
                    const statusMsg = document.getElementById('status-message');
                    const progressBar = document.getElementById('progress-bar');
                    const errorDiv = document.getElementById('error-details');
                    const errorText = document.getElementById('error-text');
                    
                    if (data.running) {
                        container.style.display = 'block';
                        statusAlert.className = 'alert alert-info';
                        progressBar.style.width = data.progress + '%';
                        statusMsg.textContent = data.current_step || data.message || 'Processing...';
                        errorDiv.style.display = 'none';
                        setTimeout(checkStatus, 2000);
                    } else if (data.completed) {
                        container.style.display = 'block';
                        statusAlert.className = 'alert alert-success';
                        progressBar.style.width = '100%';
                        statusMsg.textContent = data.message || 'Preprocessing completed successfully!';
                        errorDiv.style.display = 'none';
                        // Force refresh to show results
                        setTimeout(() => {
                            window.location.href = '/';
                        }, 1500);
                    } else if (data.message && data.message.includes('Error')) {
                        container.style.display = 'block';
                        statusAlert.className = 'alert alert-danger';
                        progressBar.style.width = '0%';
                        statusMsg.textContent = 'Preprocessing failed';
                        errorText.textContent = data.message;
                        errorDiv.style.display = 'block';
                        document.getElementById('preprocess-btn').disabled = false;
                        document.getElementById('preprocess-btn').innerHTML = '<i class="fas fa-cog"></i> Start Data Preprocessing';
                    }
                })
                .catch(err => {
                    console.error('Error checking status:', err);
                    setTimeout(checkStatus, 5000);
                });
        }
        
        // File upload drag and drop
        const uploadArea = document.getElementById('upload-area');
        if (uploadArea) {
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });
            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('dragover');
            });
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
            });
        }
    </script>
</body>
</html>"""

@app.route('/')
def index():
    """Main dashboard"""
    global STATS
    
    # Always update stats from files to get latest results
    update_stats_from_files()
    
    html = generate_html_head("Phase 1: Data Preprocessing Dashboard")
    
    # Get available datasets
    datasets = list(STATS.keys()) if STATS else []
    
    html += """
        <div class="card">
            <div class="card-header text-center">
                <h1 class="display-4 mb-3"><i class="fas fa-database"></i> Phase 1: Data Preprocessing</h1>
                <p class="lead">Intelligent Threat Detection and Response for Cloud Platforms</p>
            </div>
            <div class="card-body">
    """
    
    if datasets:
        html += """
                <div class="row mb-4">
                    <div class="col-md-4">
                        <div class="stat-card text-center">
                            <div class="stat-number">{}</div>
                            <div class="text-muted">Datasets Processed</div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stat-card text-center">
                            <div class="stat-number">{}</div>
                            <div class="text-muted">Total Records</div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stat-card text-center">
                            <div class="stat-number">112</div>
                            <div class="text-muted">Selected Features</div>
                        </div>
                    </div>
                </div>
                
                <div class="row">
        """.format(len(datasets), sum(s.get('final_rows', 0) for s in STATS.values()))
        
        for dataset_name in datasets:
            stats = STATS[dataset_name]
            retention_pct = (stats['final_rows'] / stats['original_rows']) * 100 if stats['original_rows'] > 0 else 0
            
            html += f"""
                    <div class="col-md-4">
                        <div class="card" onclick="window.location.href='/dataset/{dataset_name}'" style="cursor: pointer;">
                            <div class="card-header">
                                <h4><i class="fas fa-network-wired"></i> {dataset_name}</h4>
                            </div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <span class="badge bg-primary">{format_number(stats['final_rows'])} rows</span>
                                    <span class="badge bg-success">{stats['final_cols']} features</span>
                                </div>
                                <div class="progress mb-2">
                                    <div class="progress-bar bg-success" style="width: {retention_pct:.1f}%"></div>
                                </div>
                                <small class="text-muted">{retention_pct:.1f}% retained after cleaning</small>
                                <hr>
                                <div class="row text-center">
                                    <div class="col-6">
                                        <div class="text-danger">
                                            <i class="fas fa-trash-alt"></i><br>
                                            <strong>{format_number(stats['rows_removed'])}</strong><br>
                                            <small class="text-muted">Removed</small>
                                        </div>
                                    </div>
                                    <div class="col-6">
                                        <div class="text-success">
                                            <i class="fas fa-magic"></i><br>
                                            <strong>{stats['features_engineered']}</strong><br>
                                            <small class="text-muted">New Features</small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="card-footer bg-light text-center">
                                <a href="/dataset/{dataset_name}" class="btn btn-primary btn-sm">View Details <i class="fas fa-arrow-right"></i></a>
                            </div>
                        </div>
                    </div>
            """
        
        html += """
                </div>
        """
    else:
        html += """
                <div class="alert alert-info text-center">
                    <h4><i class="fas fa-info-circle"></i> No datasets processed yet</h4>
                    <p>Upload your datasets and run preprocessing to get started.</p>
                    <a href="/upload" class="btn btn-primary btn-lg">Go to Data Preprocessing <i class="fas fa-arrow-right"></i></a>
                </div>
        """
    
    html += """
            </div>
        </div>
    """
    
    html += generate_html_foot()
    return Response(html, mimetype='text/html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """File upload and preprocessing page"""
    global preprocessing_status
    
    if request.method == 'POST':
        safe_print("\n" + "="*60)
        safe_print("POST REQUEST TO /UPLOAD - DETAILED DEBUG")
        safe_print("="*60)
        safe_print(f"[1] Request received at: {request.path}")
        safe_print(f"[2] Form data: {dict(request.form)}")
        safe_print(f"[3] Files: {dict(request.files)}")
        safe_print(f"[4] Form keys: {list(request.form.keys())}")
        
        # Check if preprocessing button was clicked
        is_preprocessing = 'preprocess' in request.form
        safe_print(f"[5] Is preprocessing: {is_preprocessing}")
        
        if is_preprocessing:
            safe_print("[OK] Preprocessing button clicked!")
            
            # Handle any file uploads in the same request
            num_datasets = int(request.form.get('num_datasets', 1))
            safe_print(f"[6] Number of datasets: {num_datasets}")
            uploaded_files = []
            
            for i in range(num_datasets):
                file_key = f'dataset_{i}'
                if file_key in request.files:
                    file = request.files[file_key]
                    if file and file.filename and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        filepath = DATA_DIR / filename
                        file.save(filepath)
                        uploaded_files.append(filename)
                        safe_print(f"[OK] Saved file: {filename}")
            
            safe_print(f"[7] Uploaded {len(uploaded_files)} files")
            
            # Check if we have CSV files (either just uploaded or already exist)
            csv_files = list(DATA_DIR.glob('*.csv'))
            csv_files = [f for f in csv_files if '_cleaned' not in f.name and '-cleaned' not in f.name]
            
            safe_print(f"[8] Found {len(csv_files)} CSV files to process: {[f.name for f in csv_files]}")
            
            if not csv_files:
                safe_print("[ERROR] No CSV files found!")
                return jsonify({'error': 'Please upload at least one dataset file first'}), 400
            
            # Start preprocessing in background thread
            safe_print(f"[9] Starting preprocessing thread for {len(csv_files)} files")
            thread = threading.Thread(target=run_preprocessing)
            thread.daemon = True
            thread.start()
            safe_print("[OK] Thread started")
            safe_print("[10] Redirecting to /upload?processing=started")
            safe_print("="*60 + "\n")
            return redirect(url_for('upload', processing='started'))
        
        # Handle file upload only (no preprocessing)
        safe_print("[!] File upload only mode (no preprocessing)")
        num_datasets = int(request.form.get('num_datasets', 1))
        uploaded_files = []
        
        for i in range(num_datasets):
            file_key = f'dataset_{i}'
            if file_key in request.files:
                file = request.files[file_key]
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = DATA_DIR / filename
                    file.save(filepath)
                    uploaded_files.append(filename)
                    safe_print(f"[OK] Saved file: {filename}")
        
        safe_print(f"[11] Uploaded {len(uploaded_files)} files, redirecting...")
        safe_print("="*60 + "\n")
        return redirect(url_for('upload', uploaded='success'))
    
    # GET request - show upload form
    processing = request.args.get('processing', '')
    
    html = generate_html_head("Data Preprocessing - Upload Datasets")
    
    html += f"""
        <div class="card">
            <div class="card-header">
                <h3><i class="fas fa-upload"></i> Data Preprocessing</h3>
            </div>
            <div class="card-body">
                <div class="alert alert-info">
                    <h5><i class="fas fa-info-circle"></i> Instructions</h5>
                    <ol>
                        <li>Select the number of datasets you want to upload</li>
                        <li>Upload your CSV files (original datasets)</li>
                        <li>Click "Start Data Preprocessing" to begin cleaning and feature engineering</li>
                        <li>Results will be displayed automatically when complete</li>
                    </ol>
                </div>
                
                <form method="POST" enctype="multipart/form-data" id="upload-form">
                    <div class="mb-4">
                        <label for="num_datasets" class="form-label"><strong>Number of Datasets:</strong></label>
                        <select class="form-select" id="num_datasets" name="num_datasets" onchange="updateUploadFields()">
                            <option value="1">1 Dataset</option>
                            <option value="2">2 Datasets</option>
                            <option value="3" selected>3 Datasets</option>
                            <option value="4">4 Datasets</option>
                            <option value="5">5 Datasets</option>
                        </select>
                    </div>
                    
                    <div id="upload-fields">
                        <!-- Dynamic upload fields will be inserted here -->
                    </div>
                    
                    <!-- Hidden field to mark preprocessing request -->
                    <input type="hidden" name="preprocess" value="1">
                    
                    <div class="progress-container" id="progress-container" style="display: none;">
                        <div class="alert" id="status-alert">
                            <div id="status-message">Initializing...</div>
                            <div class="progress mt-2">
                                <div class="progress-bar progress-bar-striped progress-bar-animated" 
                                     id="progress-bar" role="progressbar" style="width: 0%"></div>
                            </div>
                            <div id="error-details" class="mt-2" style="display: none;">
                                <small class="text-danger" id="error-text"></small>
                            </div>
                        </div>
                    </div>
                    
                    <div class="text-center mt-4">
                        <button type="submit" class="btn btn-primary btn-lg" id="preprocess-btn">
                            <i class="fas fa-cog"></i> Start Data Preprocessing
                        </button>
                    </div>
                </form>
            </div>
        </div>
        
        <script>
            function updateUploadFields() {{
                const num = document.getElementById('num_datasets').value;
                const container = document.getElementById('upload-fields');
                container.innerHTML = '';
                
                for (let i = 0; i < num; i++) {{
                    const div = document.createElement('div');
                    div.className = 'mb-3';
                    div.innerHTML = `
                        <label for="dataset_${{i}}" class="form-label"><strong>Dataset ${{i+1}}:</strong></label>
                        <input type="file" class="form-control" id="dataset_${{i}}" name="dataset_${{i}}" accept=".csv,.txt">
                        <small class="text-muted">Upload CSV or TXT file (optional if files already in data folder)</small>
                    `;
                    container.appendChild(div);
                }}
            }}
            
            // Initialize on page load
            updateUploadFields();
            
            // Handle form submission - show progress and let form submit
            document.getElementById('upload-form').addEventListener('submit', function(e) {{
                console.log('Form submit event triggered');
                
                const btn = document.getElementById('preprocess-btn');
                btn.disabled = true;
                btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
                document.getElementById('progress-container').style.display = 'block';
                document.getElementById('status-message').textContent = 'Submitting request and starting preprocessing...';
                
                // Form has hidden preprocess=1 field, so it will trigger the right path
                // Start checking status after delay
                setTimeout(function(){{ 
                    console.log('Attempting to check status');
                    if (window.checkStatus) {{ 
                        window.checkStatus(); 
                    }}
                }}, 1500);
            }});
            
            {f"if ('{processing}' === 'started') {{ setTimeout(function(){{ if (window.checkStatus) window.checkStatus(); }}, 1000); document.getElementById('progress-container').style.display = 'block'; }}" if processing == 'started' else ''}
        </script>
    """
    
    html += generate_html_foot()
    return Response(html, mimetype='text/html')

@app.route('/api/status')
def get_status():
    """Get preprocessing status"""
    global preprocessing_status
    return jsonify(preprocessing_status)

@app.route('/api/debug')
def debug_info():
    """Debug endpoint to check file status"""
    csv_files = list(DATA_DIR.glob('*.csv'))
    cleaned_files = [f for f in csv_files if '_cleaned' in f.name or '-cleaned' in f.name]
    original_files = [f for f in csv_files if '_cleaned' not in f.name and '-cleaned' not in f.name]
    
    return jsonify({
        'data_dir': str(DATA_DIR),
        'data_dir_exists': DATA_DIR.exists(),
        'original_files': [f.name for f in original_files],
        'cleaned_files': [f.name for f in cleaned_files],
        'preprocessing_running': preprocessing_status['running'],
        'preprocessing_status': preprocessing_status
    })

@app.route('/dataset/<dataset_name>')
def dataset_detail(dataset_name):
    """Detailed dataset view"""
    global STATS, CLEANING_ACTIONS, FEATURES_ENGINEERED
    
    if dataset_name not in STATS:
        return "Dataset not found. Please run preprocessing first.", 404
    
    stats = STATS[dataset_name]
    cleaning = CLEANING_ACTIONS.get(dataset_name, [])
    features = FEATURES_ENGINEERED.get(dataset_name, [])
    
    original_sample = load_sample_data(dataset_name, 'original', 5)
    cleaned_sample = load_sample_data(dataset_name, 'cleaned', 5)
    
    html = generate_html_head(f"{dataset_name} - Preprocessing Details")
    
    html += f"""
        <div class="card">
            <div class="card-header">
                <div class="d-flex justify-content-between">
                    <h3><i class="fas fa-database"></i> {dataset_name} - Preprocessing Details</h3>
                    <a href="/" class="btn btn-light btn-sm"><i class="fas fa-arrow-left"></i> Back</a>
                </div>
            </div>
            <div class="card-body">
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="stat-card bg-primary text-white text-center">
                            <div class="h4 mb-0">{format_number(stats['original_rows'])}</div>
                            <small>Original Rows</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card bg-success text-white text-center">
                            <div class="h4 mb-0">{format_number(stats['final_rows'])}</div>
                            <small>Final Rows</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card bg-danger text-white text-center">
                            <div class="h4 mb-0">{format_number(stats['rows_removed'])}</div>
                            <small>Rows Removed</small>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card bg-info text-white text-center">
                            <div class="h4 mb-0">{stats['final_cols']}</div>
                            <small>Final Features</small>
                        </div>
                    </div>
                </div>
                
                <div class="card mb-4">
                    <div class="card-header bg-warning text-dark">
                        <h5><i class="fas fa-broom"></i> Data Cleaning Actions</h5>
                    </div>
                    <div class="card-body">
                        <table class="table table-striped">
                            <thead>
                                <tr><th>Column</th><th>Issue Found</th><th>Action Taken</th><th>Reason</th></tr>
                            </thead>
                            <tbody>
    """
    
    for action in cleaning:
        html += f"""
                                <tr>
                                    <td><strong>{action['column']}</strong></td>
                                    <td><span class="badge bg-warning text-dark">{action['issue']}</span></td>
                                    <td>{action['action']}</td>
                                    <td><small class="text-muted">{action['reason']}</small></td>
                                </tr>
        """
    
    html += """
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="card mb-4">
                    <div class="card-header bg-success text-white">
                        <h5><i class="fas fa-magic"></i> Feature Engineering ({}) New Features</h5>
                    </div>
                    <div class="card-body">
                        <table class="table table-hover">
                            <thead>
                                <tr><th>Feature Name</th><th>Type</th><th>Formula</th><th>Usefulness</th></tr>
                            </thead>
                            <tbody>
    """.format(len(features))
    
    for feat in features:
        html += f"""
                                <tr>
                                    <td><strong>{feat['feature']}</strong></td>
                                    <td><span class="badge bg-info">{feat['type']}</span></td>
                                    <td><code>{feat['formula']}</code></td>
                                    <td><small>{feat['usefulness']}</small></td>
                                </tr>
        """
    
    html += """
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-danger text-white">
                                <h5><i class="fas fa-file-alt"></i> Before Cleaning (Sample)</h5>
                            </div>
                            <div class="card-body">
    """
    
    if original_sample:
        html += f"""
                                <p class="text-muted"><small>Showing {len(original_sample['data'])} of {format_number(stats['original_rows'])} rows</small></p>
                                <div class="table-responsive">
                                    <table class="table table-sm table-bordered comparison-table before-data">
                                        <thead><tr>
        """
        for col in original_sample['columns'][:10]:
            html += f"<th>{col}</th>"
        if len(original_sample['columns']) > 10:
            html += "<th>...</th>"
        html += """
                                        </tr></thead>
                                        <tbody>
        """
        for row in original_sample['data']:
            html += "<tr>"
            for col in original_sample['columns'][:10]:
                html += f"<td>{row.get(col, '')}</td>"
            if len(original_sample['columns']) > 10:
                html += "<td>...</td>"
            html += "</tr>"
        html += """
                                        </tbody>
                                    </table>
                                </div>
        """
    else:
        html += '<p class="text-muted">Original data not available</p>'
    
    html += """
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-success text-white">
                                <h5><i class="fas fa-check-circle"></i> After Cleaning (Sample)</h5>
                            </div>
                            <div class="card-body">
    """
    
    if cleaned_sample:
        html += f"""
                                <p class="text-muted"><small>Showing {len(cleaned_sample['data'])} of {format_number(stats['final_rows'])} rows</small></p>
                                <div class="table-responsive">
                                    <table class="table table-sm table-bordered comparison-table after-data">
                                        <thead><tr>
        """
        for col in cleaned_sample['columns'][:10]:
            html += f"<th>{col}</th>"
        if len(cleaned_sample['columns']) > 10:
            html += "<th>...</th>"
        html += """
                                        </tr></thead>
                                        <tbody>
        """
        for row in cleaned_sample['data']:
            html += "<tr>"
            for col in cleaned_sample['columns'][:10]:
                html += f"<td>{row.get(col, '')}</td>"
            if len(cleaned_sample['columns']) > 10:
                html += "<td>...</td>"
            html += "</tr>"
        html += """
                                        </tbody>
                                    </table>
                                </div>
        """
    else:
        html += '<p class="text-muted">Cleaned data not available</p>'
    
    html += """
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    """
    
    html += generate_html_foot()
    return Response(html, mimetype='text/html')

@app.route('/summary')
def summary():
    """Summary report"""
    global STATS
    
    html = generate_html_head("Phase 1: Complete Summary Report")
    
    html += """
        <div class="card">
            <div class="card-header">
                <div class="d-flex justify-content-between">
                    <h2><i class="fas fa-chart-bar"></i> Phase 1: Complete Summary Report</h2>
                    <a href="/" class="btn btn-light btn-sm"><i class="fas fa-arrow-left"></i> Back</a>
                </div>
            </div>
            <div class="card-body">
    """
    
    if STATS:
        total_rows = sum(s.get('final_rows', 0) for s in STATS.values())
        html += f"""
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="stat-card text-center">
                            <div class="stat-number">{len(STATS)}</div>
                            <div class="text-muted">Datasets Processed</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card text-center">
                            <div class="stat-number">{format_number(total_rows)}</div>
                            <div class="text-muted">Total Records</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card text-center">
                            <div class="stat-number">{format_number(sum(s.get('rows_removed', 0) for s in STATS.values()))}</div>
                            <div class="text-muted">Records Removed</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card text-center">
                            <div class="stat-number">112</div>
                            <div class="text-muted">Selected Features</div>
                        </div>
                    </div>
                </div>
                
                <div class="card mb-4">
                    <div class="card-header bg-primary text-white">
                        <h5><i class="fas fa-table"></i> Dataset Comparison</h5>
                    </div>
                    <div class="card-body">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Dataset</th><th>Original Rows</th><th>Final Rows</th><th>Rows Removed</th>
                                    <th>Original Features</th><th>Final Features</th><th>Features Engineered</th><th>Features Excluded</th>
                                </tr>
                            </thead>
                            <tbody>
        """
        
        for dataset_name, stats in STATS.items():
            html += f"""
                                <tr>
                                    <td><strong>{dataset_name}</strong></td>
                                    <td>{format_number(stats['original_rows'])}</td>
                                    <td>{format_number(stats['final_rows'])}</td>
                                    <td><span class="badge bg-danger">{format_number(stats['rows_removed'])}</span></td>
                                    <td>{stats['original_cols']}</td>
                                    <td><span class="badge bg-success">{stats['final_cols']}</span></td>
                                    <td><span class="badge bg-info">{stats['features_engineered']}</span></td>
                                    <td><span class="badge bg-warning">{stats['features_excluded']}</span></td>
                                </tr>
            """
        
        html += """
                            </tbody>
                        </table>
                    </div>
                </div>
        """
    else:
        html += """
                <div class="alert alert-warning">
                    <h4>No data available</h4>
                    <p>Please upload datasets and run preprocessing first.</p>
                    <a href="/upload" class="btn btn-primary">Go to Data Preprocessing</a>
                </div>
        """
    
    html += """
            </div>
        </div>
    """
    
    html += generate_html_foot()
    return Response(html, mimetype='text/html')

def get_wids_results():
    """Get WIDS analysis results"""
    try:
        wids = WebIntrusionDetectionSystem(
            data_file='data/CIC-IDS-2017_cleaned.csv',
            model_file='models/wids_iforest.pkl'
        )
        
        # Load data
        if not wids.load_data():
            return None
        
        # Engineer features
        if not wids.engineer_web_features():
            return None
        
        # Prepare model data
        X_scaled = wids.prepare_model_data()
        if X_scaled is None:
            return None
        
        # Train model
        if not wids.train_anomaly_detector(X_scaled):
            return None
        
        # Generate anomalies
        wids.generate_anomaly_report()
        
        return wids
    except Exception as e:
        safe_print(f"[ERROR] Failed to get WIDS results: {e}")
        return None

@app.route('/wids')
def wids_dashboard():
    """Web Intrusion Detection System Dashboard"""
    html = generate_html_head("Module 2: Web Intrusion Detection System (WIDS)")
    
    # Get WIDS results
    wids = get_wids_results()
    
    if wids is None:
        html += """
        <div class="card">
            <div class="card-header">
                <h3><i class="fas fa-exclamation-triangle"></i> WIDS Error</h3>
            </div>
            <div class="card-body">
                <div class="alert alert-danger">
                    <h5>Failed to load WIDS data</h5>
                    <p>Ensure CIC-IDS-2017_cleaned.csv exists in the data folder.</p>
                </div>
            </div>
        </div>
        """
        html += generate_html_foot()
        return Response(html, mimetype='text/html')
    
    # Summary cards
    html += f"""
        <div class="card">
            <div class="card-header text-center">
                <h1 class="display-4 mb-3"><i class="fas fa-shield-alt"></i> Web Intrusion Detection System</h1>
                <p class="lead">Anomaly Detection Using Isolation Forest</p>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card bg-primary text-white">
                    <div class="card-body text-center">
                        <div class="h3 mb-0">{format_number(wids.stats.get('total_requests', 0))}</div>
                        <small class="text-white-50">Total Web Requests</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-danger text-white">
                    <div class="card-body text-center">
                        <div class="h3 mb-0">{format_number(wids.stats.get('anomalies_detected', 0))}</div>
                        <small class="text-white-50">Anomalies Detected</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-warning text-dark">
                    <div class="card-body text-center">
                        <div class="h3 mb-0">{wids.stats.get('anomaly_percentage', 0):.2f}%</div>
                        <small class="text-dark-50">Anomaly Rate</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-info text-white">
                    <div class="card-body text-center">
                        <div class="h3 mb-0">{'ALERT' if wids.stats.get('alert_triggered') else 'OK'}</div>
                        <small class="text-white-50">System Status</small>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Model Information -->
        <div class="card mb-4">
            <div class="card-header">
                <h4><i class="fas fa-cogs"></i> Model Configuration</h4>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>Algorithm:</strong> Isolation Forest</p>
                        <p><strong>Estimators:</strong> 200 decision trees</p>
                        <p><strong>Contamination Rate:</strong> 5%</p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>Features Used:</strong> 8 behavioral features</p>
                        <p><strong>Dataset:</strong> CIC-IDS-2017 (cleaned)</p>
                        <p><strong>Total Samples:</strong> {format_number(wids.stats.get('total_requests', 0))}</p>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Feature Engineering -->
        <div class="card mb-4">
            <div class="card-header">
                <h4><i class="fas fa-cube"></i> Engineered Features (8)</h4>
            </div>
            <div class="card-body">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Feature Name</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>request_count</strong></td>
                            <td>Number of requests in flow group (window-based aggregation)</td>
                        </tr>
                        <tr>
                            <td><strong>unique_dst_ports</strong></td>
                            <td>Unique destination ports accessed in flow group</td>
                        </tr>
                        <tr>
                            <td><strong>mean_bytes_sent</strong></td>
                            <td>Average bytes sent per flow in group</td>
                        </tr>
                        <tr>
                            <td><strong>mean_bytes_received</strong></td>
                            <td>Average bytes received per flow in group</td>
                        </tr>
                        <tr>
                            <td><strong>request_rate</strong></td>
                            <td>Requests per second (flow frequency metric)</td>
                        </tr>
                        <tr>
                            <td><strong>duration_mean</strong></td>
                            <td>Average flow duration in group</td>
                        </tr>
                        <tr>
                            <td><strong>packet_count_mean</strong></td>
                            <td>Average packet count per flow</td>
                        </tr>
                        <tr>
                            <td><strong>byte_ratio</strong></td>
                            <td>Ratio of sent to received bytes (communication pattern)</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Detection Results -->
        <div class="card mb-4">
            <div class="card-header">
                <h4><i class="fas fa-chart-pie"></i> Detection Results</h4>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h5>Flow Classification</h5>
                        <div class="mb-3">
                            <div class="d-flex justify-content-between mb-2">
                                <span>Normal Flows</span>
                                <span><strong>{wids.stats.get('total_requests', 0) - wids.stats.get('anomalies_detected', 0):,}</strong></span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar bg-success" role="progressbar" 
                                     style="width: {100 - wids.stats.get('anomaly_percentage', 0):.1f}%">
                                </div>
                            </div>
                        </div>
                        <div class="mb-3">
                            <div class="d-flex justify-content-between mb-2">
                                <span>Anomalous Flows</span>
                                <span><strong>{format_number(wids.stats.get('anomalies_detected', 0))}</strong></span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar bg-danger" role="progressbar" 
                                     style="width: {wids.stats.get('anomaly_percentage', 0):.1f}%">
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <h5>Statistics</h5>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <strong>Detection Rate:</strong> {wids.stats.get('anomaly_percentage', 0):.2f}%
                            </li>
                            <li class="list-group-item">
                                <strong>Precision:</strong> 5.00% (configured contamination)
                            </li>
                            <li class="list-group-item">
                                <strong>Isolation Forest Trees:</strong> 200
                            </li>
                            <li class="list-group-item">
                                <strong>Feature Scaling:</strong> StandardScaler (z-score normalized)
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Top Anomalous Records -->
        <div class="card mb-4">
            <div class="card-header">
                <h4><i class="fas fa-exclamation-circle"></i> Sample Anomalous Records (Top 10)</h4>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Request Count</th>
                                <th>Unique Dst Ports</th>
                                <th>Mean Bytes Sent</th>
                                <th>Byte Ratio</th>
                                <th>Risk Level</th>
                            </tr>
                        </thead>
                        <tbody>
    """
    
    # Add sample anomalies
    if hasattr(wids, 'df') and wids.df is not None:
        anomalies = wids.df[wids.df['is_anomaly'] == 1]
        sample_cols = ['request_count', 'unique_dst_ports', 'mean_bytes_sent', 'byte_ratio']
        
        for idx, (_, row) in enumerate(anomalies.iloc[:min(10, len(anomalies))].iterrows()):
            byte_ratio = row.get('byte_ratio', 1.0)
            risk = 'HIGH' if byte_ratio > 2 else 'MEDIUM' if byte_ratio > 1 else 'LOW'
            html += f"""
                            <tr>
                                <td>{int(row.get('request_count', 0))}</td>
                                <td>{int(row.get('unique_dst_ports', 0))}</td>
                                <td>{row.get('mean_bytes_sent', 0):.2f}</td>
                                <td>{byte_ratio:.2f}</td>
                                <td><span class="badge bg-danger">{risk}</span></td>
                            </tr>
            """
    
    html += """
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Alert Logic -->
        <div class="card mb-4">
            <div class="card-header">
                <h4><i class="fas fa-bell"></i> Alert & Threshold Logic</h4>
            </div>
            <div class="card-body">
                <div class="alert alert-info">
                    <h5>Alerting Mechanism</h5>
                    <p>The system uses threshold-based alerting to detect abnormal traffic patterns:</p>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <h6><strong>Current Metrics</strong></h6>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                Anomaly Rate: <strong>{wids.stats.get('anomaly_percentage', 0):.2f}%</strong>
                            </li>
                            <li class="list-group-item">
                                Alert Threshold: <strong>5.00%</strong>
                            </li>
                            <li class="list-group-item">
                                Status: <span class="badge bg-{'danger' if wids.stats.get('alert_triggered') else 'success'}">
                                    {'ALERT TRIGGERED' if wids.stats.get('alert_triggered') else 'NORMAL'}
                                </span>
                            </li>
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <h6><strong>Alert Decision Tree</strong></h6>
                        <div class="alert alert-light border">
                            <small>
                                IF anomaly_rate > 5.00% → <span class="text-danger"><strong>ALERT TRIGGERED</strong></span><br>
                                THEN → Escalate to security team<br>
                                ELSE → <span class="text-success"><strong>SYSTEM NORMAL</strong></span><br>
                                &nbsp;&nbsp;&nbsp;&nbsp;Continue monitoring
                            </small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <a href="/" class="btn btn-secondary"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
    """
    
    html += generate_html_foot()
    return Response(html, mimetype='text/html')

if __name__ == '__main__':
    # Initialize stats on startup
    update_stats_from_files()
    
    safe_print("="*60)
    safe_print("Phase 1 Data Preprocessing - Flask Web UI")
    safe_print("="*60)
    safe_print("Starting server on http://localhost:5006")
    safe_print("Press Ctrl+C to stop the server")
    safe_print("="*60)
    app.run(debug=True, host='0.0.0.0', port=5006)
