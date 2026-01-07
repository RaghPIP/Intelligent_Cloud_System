# Phase 1: Data Preprocessing

## 1. Data Sources

### 1.1 Network Traffic Classifier Module

The Network Traffic Classifier module utilizes three benchmark datasets to ensure comprehensive coverage of network attack patterns:

#### 1.1.1 NSL-KDD Dataset
- **Source**: Archive (2) - Contains preprocessed KDD Cup 1999 data with redundant records removed
- **Files**: 
  - `KDDTrain+_20Percent.txt` (Training set)
  - `KDDTest+.txt` (Test set)
  - `KDDTest-21.txt` (Test set with 21 attack types)
- **Format**: CSV-compatible text files with 41 features + 1 label column
- **Attack Categories**: DoS, Probe, R2L, U2R, Normal
- **Total Records**: ~125,000 training records, ~22,500 test records
- **Rationale**: NSL-KDD addresses redundancy issues in original KDD Cup 99, providing cleaner baseline for network intrusion detection

#### 1.1.2 UNSW-NB15 Dataset
- **Source**: Archive (3) - Modern network traffic dataset
- **Files**: 
  - `UNSW_NB15_training-set.parquet` (Training set)
  - `UNSW_NB15_testing-set.parquet` (Test set)
- **Format**: Parquet format with 49 features + 1 label column
- **Attack Categories**: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms, Normal
- **Total Records**: ~175,000 training records, ~82,000 test records
- **Rationale**: UNSW-NB15 provides contemporary attack patterns and modern network protocols, complementing NSL-KDD's historical perspective

#### 1.1.3 CIC-IDS-2017 Dataset
- **Source**: Archive (1) - Canadian Institute for Cybersecurity dataset
- **Files**: 8 CSV files representing different attack scenarios:
  - `Monday-WorkingHours.pcap_ISCX.csv` (Benign traffic)
  - `Tuesday-WorkingHours.pcap_ISCX.csv` (Benign traffic)
  - `Wednesday-workingHours.pcap_ISCX.csv` (Benign traffic)
  - `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` (Web attacks)
  - `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` (Infiltration attacks)
  - `Friday-WorkingHours-Morning.pcap_ISCX.csv` (Benign traffic)
  - `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` (Port scan attacks)
  - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (DDoS attacks)
- **Format**: CSV files with 78 flow-based features + 1 label column
- **Attack Categories**: DDoS, Port Scan, Web Attack, Infiltration, Benign
- **Total Records**: ~2.8 million flow records across all files
- **Rationale**: CIC-IDS-2017 provides realistic network flow features extracted from packet captures, suitable for real-time flow-based detection

### 1.2 Web Intrusion Detection System (WIDS) Module

#### 1.2.1 HTTP Access Logs
- **Source**: Web server access logs (Apache/Nginx format)
- **Format**: Common Log Format (CLF) or Extended Log Format (ELF)
- **Typical Fields**:
  - Remote IP address
  - Timestamp
  - HTTP method (GET, POST, PUT, DELETE, etc.)
  - Requested URL/URI
  - HTTP version
  - Status code
  - Response size
  - User-Agent string
  - Referer
  - Request headers (optional)
- **Attack Patterns**: SQL injection, XSS, Path traversal, Command injection, Brute force, CSRF
- **Collection Method**: Log aggregation from multiple web servers in cloud environment
- **Rationale**: HTTP logs capture application-layer attacks that network-level features may miss, essential for comprehensive cloud security

### 1.3 Malware Analysis System Module

#### 1.3.1 Windows Executable Binaries
- **Source**: VirusTotal-based dataset (public malware repositories)
- **Format**: PE (Portable Executable) files - Windows .exe and .dll binaries
- **File Types**: 
  - Executables (.exe)
  - Dynamic Link Libraries (.dll)
  - System files (.sys)
- **Malware Families**: Trojans, Worms, Ransomware, Rootkits, Backdoors, Spyware, Adware
- **Collection Method**: Aggregated from VirusTotal API and public malware repositories (VX Underground, MalwareBazaar)
- **Rationale**: Binary-level analysis provides deep insight into malware behavior patterns, complementing network and web-layer detection

---

## 2. Data Cleaning

### 2.1 Network Traffic Data Cleaning

#### 2.1.1 Missing Value Handling

**CIC-IDS-2017**:
- **Issue**: Some flow records may contain missing values in statistical features (e.g., IAT statistics for single-packet flows)
- **Strategy**: 
  - **Numerical features**: Replace missing values with 0 for features where absence indicates no activity (e.g., backward packet statistics for unidirectional flows)
  - **Statistical features**: Replace missing values with median of the feature column for features requiring multiple packets (e.g., IAT mean/std)
  - **Justification**: Median preserves distribution characteristics while handling outliers better than mean

**NSL-KDD**:
- **Issue**: Minimal missing values due to preprocessed nature
- **Strategy**: Forward-fill for temporal sequences, median imputation for statistical features
- **Justification**: NSL-KDD is already cleaned, but edge cases require consistent handling

**UNSW-NB15**:
- **Issue**: Some features may have NaN values in parquet format
- **Strategy**: 
  - Drop records with >50% missing features (likely corrupted)
  - Impute remaining missing values using feature-specific strategies:
    - Categorical: Mode imputation
    - Numerical: Median imputation
- **Justification**: Preserves data integrity while maintaining dataset size

#### 2.1.2 Duplicate Record Handling

**CIC-IDS-2017**:
- **Issue**: Potential duplicate flow records across different time windows
- **Strategy**: 
  - Identify duplicates based on: Source IP, Destination IP, Source Port, Destination Port, Protocol, Flow Duration
  - Retain first occurrence, flag subsequent duplicates
  - For training: Remove exact duplicates
  - For real-time: Allow duplicates (different time windows represent different flows)
- **Justification**: Duplicate removal prevents model bias toward frequent benign flows

**NSL-KDD**:
- **Issue**: NSL-KDD already addresses redundancy, but some duplicates may persist
- **Strategy**: Remove exact duplicate records based on all 41 features
- **Justification**: Aligns with NSL-KDD's design philosophy of reducing redundancy

**UNSW-NB15**:
- **Strategy**: Remove exact duplicates based on all feature columns
- **Justification**: Prevents overfitting to repeated patterns

#### 2.1.3 Data Type Conversion and Normalization

**Protocol Encoding**:
- Convert protocol strings (tcp, udp, icmp) to numerical codes: TCP=0, UDP=1, ICMP=2
- **Justification**: Required for numerical algorithms (Random Forest, Isolation Forest, LSTM)

**Service Encoding**:
- One-hot encode service types (http, ftp, smtp, etc.) for NSL-KDD
- **Justification**: Categorical features require encoding for tree-based and neural network models

**Flag Encoding**:
- Convert connection flags (SF, S0, S1, etc.) to binary features
- **Justification**: Flags indicate connection state, critical for attack detection

**Port Normalization**:
- Normalize port numbers to [0, 1] range: `normalized_port = port / 65535`
- **Justification**: Prevents high-magnitude port numbers from dominating feature space

### 2.2 Web Log Data Cleaning

#### 2.2.1 Log Parsing and Standardization

**Format Normalization**:
- Parse various log formats (CLF, ELF, JSON) into standardized schema
- Extract core fields: IP, timestamp, method, URI, status_code, size, user_agent, referer
- **Justification**: Consistent schema enables unified feature engineering

**Timestamp Parsing**:
- Convert various timestamp formats to Unix epoch or ISO 8601
- Handle timezone inconsistencies (normalize to UTC)
- **Justification**: Temporal features require consistent time representation

#### 2.2.2 Invalid Record Filtering

**Filter Criteria**:
- Remove records with:
  - Invalid IP addresses (not IPv4/IPv6 format)
  - Malformed URIs (containing control characters)
  - Status codes outside valid HTTP range (100-599)
  - Negative response sizes
- **Justification**: Invalid records introduce noise and may cause feature extraction errors

**Bot Traffic Handling**:
- Identify and flag bot traffic using User-Agent patterns
- Option 1: Remove bot traffic (if focusing on human-initiated attacks)
- Option 2: Retain with separate label (if bot attacks are relevant)
- **Justification**: Depends on use case; for cloud security, bot attacks are relevant

#### 2.2.3 Missing Value Handling

**Strategy**:
- **User-Agent**: Replace missing with "Unknown"
- **Referer**: Replace missing with "Direct" (indicates direct access)
- **Query Parameters**: Empty string if absent
- **Justification**: Missing values in web logs often carry semantic meaning (e.g., no referer = direct access)

### 2.3 Malware Binary Data Cleaning

#### 2.3.1 File Validation

**PE Header Validation**:
- Verify valid PE header structure (MZ signature, PE signature)
- Reject corrupted or non-PE files
- **Justification**: Invalid PE files cannot be analyzed using standard PE parsers

**File Size Filtering**:
- Remove files < 1 KB (likely corrupted or incomplete)
- Remove files > 100 MB (computational constraints for real-time analysis)
- **Justification**: Balances analysis depth with processing time requirements

#### 2.3.2 Extraction Error Handling

**Strategy**:
- If feature extraction fails (e.g., corrupted sections), mark feature as missing
- Use median/mode imputation for missing features
- Flag records with >30% missing features for manual review
- **Justification**: Some malware uses obfuscation that breaks standard parsers; imputation preserves other useful features

---

## 3. Feature Engineering

### 3.1 Network Traffic Feature Engineering

#### 3.1.1 Statistical Features (Derived from Existing)

**Flow Statistics**:
- **Packet Ratio**: `Total Fwd Packets / Total Backward Packets` (handles division by zero)
- **Byte Ratio**: `Total Length of Fwd Packets / Total Length of Bwd Packets`
- **Asymmetry Score**: `|Fwd Packets - Bwd Packets| / (Fwd Packets + Bwd Packets)`
- **Justification**: Ratios capture communication patterns; asymmetry indicates unidirectional attacks (e.g., DDoS)

**Temporal Features**:
- **Flow Rate**: `Total Packets / Flow Duration` (packets per second)
- **Burstiness**: `Flow IAT Std / Flow IAT Mean` (coefficient of variation)
- **Inter-arrival Time Skewness**: Statistical third moment of IAT distribution
- **Justification**: Temporal patterns distinguish attack traffic (bursty, regular intervals) from normal traffic

**Size Distribution Features**:
- **Packet Size Coefficient of Variation**: `Packet Length Std / Packet Length Mean`
- **Size Entropy**: Shannon entropy of packet size distribution
- **Justification**: Attack traffic often exhibits different size distributions than normal traffic

#### 3.1.2 Behavioral Features

**Connection State Features**:
- **Flag Combination Score**: Weighted sum of TCP flags (SYN=1, ACK=2, FIN=4, RST=8, PSH=16, URG=32)
- **Half-Open Connection Indicator**: Binary feature (SYN without ACK)
- **Justification**: Flag patterns indicate connection state; half-open connections suggest port scanning

**Protocol-Specific Features**:
- **TCP Window Size Ratio**: `Init_Win_bytes_forward / Init_Win_bytes_backward`
- **TCP Sequence Number Patterns**: Extract patterns from sequence numbers (if available)
- **Justification**: Protocol-specific anomalies indicate attacks (e.g., TCP window manipulation)

**Port-Based Features**:
- **Well-Known Port Indicator**: Binary (port < 1024)
- **Ephemeral Port Indicator**: Binary (port 49152-65535)
- **Port Entropy**: If multiple ports per IP, calculate entropy
- **Justification**: Port usage patterns distinguish normal services from scanning/backdoor activities

#### 3.1.3 Temporal Aggregation Features (for LSTM)

**Time-Window Aggregation**:
- Aggregate flows into fixed time windows (e.g., 1-minute windows)
- Calculate per-window statistics:
  - Flow count per IP
  - Unique destination count per source IP
  - Average flow duration
  - Attack ratio (if labels available)
- **Justification**: Temporal sequences enable LSTM to learn attack progression patterns

**Sliding Window Features**:
- For each flow, calculate statistics of previous N flows from same source IP
- Features: Mean packet count, Mean duration, Attack frequency
- **Justification**: Contextual features help detect coordinated attacks

### 3.2 Web Log Feature Engineering

#### 3.2.1 URL-Based Features

**Path Depth**:
- Count directory levels: `len(URI.split('/')) - 1`
- **Justification**: Deep paths may indicate path traversal attempts

**URL Length**:
- Character count of full URI
- **Justification**: Excessively long URLs may contain injection payloads

**Special Character Frequency**:
- Count occurrences of: `'`, `"`, `;`, `--`, `/*`, `*/`, `%`, `&`, `=`
- **Justification**: SQL injection and XSS attacks use specific character patterns

**File Extension Extraction**:
- Extract and encode file extensions (.php, .jsp, .exe, etc.)
- **Justification**: Certain extensions are targeted more frequently

**Parameter Count**:
- Count query parameters: `len(parse_qs(URI))`
- **Justification**: Excessive parameters may indicate probing

#### 3.2.2 Request Pattern Features

**HTTP Method Encoding**:
- One-hot encode: GET, POST, PUT, DELETE, HEAD, OPTIONS
- **Justification**: Different methods have different attack vectors

**Status Code Categories**:
- Group status codes: 2xx (Success), 3xx (Redirect), 4xx (Client Error), 5xx (Server Error)
- Calculate success rate per IP: `count(2xx) / total_requests`
- **Justification**: High error rates may indicate scanning or failed attacks

**Request Frequency**:
- Requests per minute per IP
- Requests per minute per URI
- **Justification**: High frequency indicates brute force or DDoS

#### 3.2.3 User-Agent and Referer Features

**User-Agent Parsing**:
- Extract browser type, OS, device type
- Flag known bot/crawler patterns
- **Justification**: Bot traffic patterns differ from human traffic

**Referer Analysis**:
- External referer indicator (binary)
- Self-referer indicator (binary)
- Missing referer frequency per IP
- **Justification**: Referer patterns indicate attack vectors (e.g., CSRF requires external referer)

#### 3.2.4 Temporal Features

**Time-Based Patterns**:
- Hour of day (0-23)
- Day of week (0-6)
- Is weekend (binary)
- Is business hours (binary, 9 AM - 5 PM)
- **Justification**: Attack patterns may correlate with time (e.g., off-hours attacks)

**Request Inter-arrival Time**:
- Time between consecutive requests from same IP
- Mean, std, min, max of IAT per IP
- **Justification**: Burst patterns indicate automated attacks

### 3.3 Malware Binary Feature Engineering

#### 3.3.1 PE Header Features

**Section Characteristics**:
- Number of sections
- Section entropy (high entropy indicates packing/encryption)
- Executable section count
- Writable section count
- **Justification**: Malware often uses unusual section configurations

**Import/Export Features**:
- Number of imported DLLs
- Number of imported functions
- Suspicious API imports (e.g., VirtualAlloc, CreateRemoteThread)
- **Justification**: API usage patterns reveal malicious functionality

**Resource Features**:
- Number of resources
- Resource types present
- **Justification**: Resources may contain embedded payloads

#### 3.3.2 Statistical Features

**Byte-Level Statistics**:
- Byte entropy (overall file entropy)
- Null byte percentage
- Printable character percentage
- **Justification**: Packed/encrypted malware exhibits high entropy

**String Features**:
- Number of printable strings
- Average string length
- Suspicious string patterns (e.g., "password", "keylog", "backdoor")
- **Justification**: Strings reveal functionality and communication endpoints

#### 3.3.3 Behavioral Features (Static Analysis)

**Control Flow Features**:
- Number of functions
- Average function size
- Cyclomatic complexity (if available)
- **Justification**: Malware often has complex control flow for obfuscation

**Opcode Sequences**:
- Extract opcode sequences from disassembly
- Calculate n-gram frequencies (2-grams, 3-grams)
- **Justification**: Opcode patterns are robust to packing (after unpacking)

---

## 4. Feature Selection

### 4.1 Network Traffic Feature Selection

#### 4.1.1 Features INCLUDED

**Core Flow Features** (Essential for all models):
- Flow Duration
- Total Fwd/Backward Packets
- Total Fwd/Backward Bytes
- Flow Bytes/s, Flow Packets/s
- **Justification**: Fundamental flow characteristics; low computational cost, high discriminative power

**Packet Size Statistics** (Included):
- Fwd/Bwd Packet Length Mean, Std, Min, Max
- Packet Length Mean, Std, Variance
- **Justification**: Size patterns distinguish attack types (e.g., small packets in port scans)

**Inter-arrival Time Features** (Included):
- Flow IAT Mean, Std, Max, Min
- Fwd/Bwd IAT Mean, Std, Max, Min
- **Justification**: Temporal patterns critical for detecting DDoS, port scans; required for LSTM sequences

**TCP Flag Features** (Included):
- FIN, SYN, RST, PSH, ACK, URG flag counts
- Flag combination score
- **Justification**: Flags indicate connection state and attack patterns (e.g., SYN flood)

**Protocol and Port Features** (Included):
- Protocol (encoded)
- Destination Port (normalized)
- Well-known port indicator
- **Justification**: Protocol and port usage patterns are strong attack indicators

**Window Size Features** (Included):
- Init_Win_bytes_forward/backward
- **Justification**: Window size anomalies indicate TCP-based attacks

**Derived Statistical Features** (Included):
- Packet/Byte ratios
- Asymmetry score
- Burstiness (IAT coefficient of variation)
- **Justification**: Ratios capture relative patterns, reducing absolute value dependencies

#### 4.1.2 Features DISCARDED

**Redundant Features** (Discarded):
- **Fwd Header Length** (appears twice in CIC-IDS-2017) - Keep only one instance
- **Duplicate statistical measures** - If correlation > 0.95, keep one
- **Justification**: Redundancy increases model complexity without adding information; violates Occam's razor

**High-Correlation Features** (Discarded after analysis):
- Features with correlation > 0.90 with other features
- Example: If "Total Fwd Packets" correlates 0.95 with "Fwd Packets/s × Flow Duration", discard the derived feature
- **Justification**: Multicollinearity causes instability in tree-based models and overfitting in neural networks

**Low-Variance Features** (Discarded):
- Features with variance < threshold (e.g., < 0.01 after normalization)
- Example: Features that are constant across >99% of records
- **Justification**: No discriminative power; adds noise

**Computationally Expensive Features** (Discarded for real-time):
- Deep packet inspection features requiring full packet payload analysis
- Features requiring multi-flow aggregation in real-time (if not pre-computed)
- **Justification**: Real-time detection requires low-latency feature extraction; complex features violate scalability constraints

**Temporal Leakage Features** (Discarded):
- Features requiring future information (e.g., "Total flows after this flow")
- Features using test-time labels
- **Justification**: Prevents data leakage; ensures features are extractable at prediction time

**Dataset-Specific Identifiers** (Discarded):
- Record IDs, timestamps (if not used for temporal features)
- Source/Destination IP addresses (for training; may be used for inference grouping)
- **Justification**: Identifiers cause overfitting; IP addresses may be used for grouping in production but not as direct features

### 4.2 Web Log Feature Selection

#### 4.2.1 Features INCLUDED

**Request Characteristics** (Included):
- HTTP Method (one-hot encoded)
- URI Length
- Path Depth
- Parameter Count
- File Extension
- **Justification**: Core request characteristics directly related to attack patterns

**Status Code Features** (Included):
- Status Code (categorical)
- Status Code Category (2xx, 3xx, 4xx, 5xx)
- Success Rate per IP (aggregated)
- **Justification**: Error patterns indicate attack attempts

**Special Character Features** (Included):
- SQL Injection character counts (`'`, `--`, `/*`)
- XSS character counts (`<`, `>`, `script`)
- URL encoding percentage (`%`)
- **Justification**: Direct indicators of injection attacks

**Temporal Features** (Included):
- Hour of Day, Day of Week
- Request Frequency per IP
- Inter-arrival Time statistics
- **Justification**: Temporal patterns distinguish automated attacks from human behavior

**User-Agent Features** (Included):
- Bot Indicator
- Browser Type (encoded)
- **Justification**: Bot traffic patterns differ; some attacks use specific user agents

#### 4.2.2 Features DISCARDED

**High-Cardinality Categorical Features** (Discarded or Aggregated):
- **Full URI Path** - Discard raw URI, use derived features (depth, length, parameters)
- **Full User-Agent String** - Extract key components instead
- **Justification**: High cardinality causes overfitting; tree-based models struggle with sparse categories

**Personally Identifiable Information** (Discarded):
- **Full IP Addresses** (for training) - Use aggregated features instead
- **Email addresses in logs** (if present)
- **Justification**: Privacy compliance (GDPR, CCPA); IP addresses can be used for grouping but not as direct features

**Noisy Features** (Discarded):
- **Referer Full URL** - Use binary indicators (external/missing) instead
- **Query Parameter Values** - Use parameter count and special character presence
- **Justification**: Raw values are too variable; derived features capture patterns

**Redundant Features** (Discarded):
- **Response Size** (if highly correlated with status code)
- **HTTP Version** (minimal variation in modern logs)
- **Justification**: Redundancy adds no value, increases complexity

### 4.3 Malware Binary Feature Selection

#### 4.3.1 Features INCLUDED

**PE Structure Features** (Included):
- Number of Sections
- Section Entropy (mean, max)
- Executable Section Count
- **Justification**: Structural features are robust to minor obfuscation

**Import Features** (Included):
- Number of Imported DLLs
- Number of Imported Functions
- Suspicious API Count (weighted by maliciousness score)
- **Justification**: API usage is strong indicator of functionality

**Entropy Features** (Included):
- Overall File Entropy
- Section Entropy Statistics
- **Justification**: High entropy indicates packing/encryption (common in malware)

**String Features** (Included):
- Suspicious String Count
- Average String Length
- **Justification**: Strings reveal functionality and communication patterns

**Resource Features** (Included):
- Number of Resources
- Resource Type Diversity
- **Justification**: Embedded resources may contain payloads

#### 4.3.2 Features DISCARDED

**File Path Features** (Discarded):
- **Full File Path** - Not available at analysis time in cloud environment
- **File Name** - Can be easily changed, not reliable
- **Justification**: Paths are not intrinsic to malware; focus on binary content

**Timestamp Features** (Discarded):
- **Compilation Timestamp** - Can be forged
- **Justification**: Easily manipulated, not reliable for detection

**Size-Dependent Features** (Normalized, not discarded):
- **Raw File Size** - Use normalized size or size categories
- **Justification**: Size varies widely; normalization prevents bias

**Obfuscation-Specific Features** (Discarded if unreliable):
- Features that fail on heavily obfuscated samples
- **Justification**: Need features that work even when obfuscation breaks parsers

**High-Dimensional Features** (Dimensionality Reduction):
- **Raw Opcode Sequences** - Use n-gram frequencies or embeddings instead
- **Justification**: Raw sequences are too high-dimensional; aggregated features are more robust

---

## 5. Final Dataset Structure

### 5.1 Network Traffic Dataset

#### 5.1.1 Combined Dataset Schema

After merging NSL-KDD, UNSW-NB15, and CIC-IDS-2017:

**Feature Count**: 65 features (after feature selection and engineering)

**Feature Categories**:
1. **Basic Flow Features** (8 features):
   - Flow Duration
   - Total Fwd/Backward Packets
   - Total Fwd/Backward Bytes
   - Flow Bytes/s
   - Flow Packets/s

2. **Packet Size Features** (12 features):
   - Fwd/Bwd Packet Length (Mean, Std, Min, Max)
   - Packet Length (Mean, Std, Variance)
   - Average Packet Size
   - Packet Size Coefficient of Variation

3. **Temporal Features** (14 features):
   - Flow IAT (Mean, Std, Max, Min)
   - Fwd IAT (Mean, Std, Max, Min)
   - Bwd IAT (Mean, Std, Max, Min)
   - Burstiness Score
   - Flow Rate

4. **Protocol and Port Features** (5 features):
   - Protocol (encoded)
   - Destination Port (normalized)
   - Well-known Port Indicator
   - Ephemeral Port Indicator
   - Port Entropy (per IP, if aggregated)

5. **TCP Flag Features** (8 features):
   - FIN, SYN, RST, PSH, ACK, URG Flag Counts
   - Flag Combination Score
   - Half-Open Connection Indicator

6. **Window and Connection Features** (6 features):
   - Init_Win_bytes_forward/backward
   - Window Size Ratio
   - Down/Up Ratio
   - Active/Idle Time Statistics (Mean, Std)

7. **Derived Statistical Features** (8 features):
   - Packet Ratio
   - Byte Ratio
   - Asymmetry Score
   - Size Entropy
   - Flow State Indicators

8. **Temporal Aggregation Features** (4 features, for LSTM):
   - Flow Count per IP (time window)
   - Unique Destination Count (time window)
   - Attack Frequency (time window)
   - Previous Flow Statistics (sliding window)

**Label Encoding**:
- **Multi-class**: 0=Normal, 1=DDoS, 2=PortScan, 3=WebAttack, 4=Infiltration, 5=Probe, 6=R2L, 7=U2R, 8=Other
- **Binary**: 0=Normal, 1=Attack (aggregated)

**Dataset Splits**:
- **Training**: 70% (combined from all three datasets)
- **Validation**: 15%
- **Test**: 15%

**Class Distribution** (after balancing):
- Normal: ~40%
- DDoS: ~15%
- PortScan: ~12%
- WebAttack: ~10%
- Other attacks: ~23%

### 5.2 Web Log Dataset

#### 5.2.1 Feature Schema

**Feature Count**: 42 features

**Feature Categories**:
1. **Request Features** (8 features):
   - HTTP Method (one-hot: 6 methods)
   - URI Length
   - Path Depth
   - Parameter Count
   - File Extension (encoded: 10 common extensions)

2. **Status Code Features** (4 features):
   - Status Code Category (2xx, 3xx, 4xx, 5xx)
   - Success Rate per IP
   - Error Rate per IP
   - Status Code (categorical)

3. **Injection Pattern Features** (8 features):
   - SQL Injection Character Count (`'`, `--`, `/*`, `*/`)
   - XSS Character Count (`<`, `>`, `script`)
   - Command Injection Indicators (`;`, `|`, `&`)
   - URL Encoding Percentage

4. **Temporal Features** (6 features):
   - Hour of Day (0-23)
   - Day of Week (0-6)
   - Is Weekend (binary)
   - Is Business Hours (binary)
   - Requests per Minute (per IP)
   - Inter-arrival Time Statistics (Mean, Std)

5. **User-Agent Features** (4 features):
   - Bot Indicator
   - Browser Type (encoded: 5 types)
   - OS Type (encoded: 4 types)
   - User-Agent Length

6. **Referer Features** (3 features):
   - External Referer Indicator
   - Self-Referer Indicator
   - Missing Referer Frequency

7. **Aggregated IP Features** (9 features):
   - Unique URI Count per IP
   - Unique Status Code Count per IP
   - Request Frequency per IP
   - Error Rate per IP
   - Suspicious Pattern Frequency

**Label Encoding**:
- **Multi-class**: 0=Normal, 1=SQL Injection, 2=XSS, 3=Path Traversal, 4=Command Injection, 5=Brute Force, 6=CSRF, 7=Other
- **Binary**: 0=Normal, 1=Attack

**Dataset Characteristics**:
- **Training Size**: ~500,000 log entries
- **Time Window**: 30 days of web server logs
- **Class Distribution**: Normal: ~85%, Attacks: ~15% (after synthetic attack injection if needed)

### 5.3 Malware Binary Dataset

#### 5.3.1 Feature Schema

**Feature Count**: 38 features

**Feature Categories**:
1. **PE Structure Features** (8 features):
   - Number of Sections
   - Section Entropy (Mean, Max, Std)
   - Executable Section Count
   - Writable Section Count
   - Section Alignment

2. **Import Features** (10 features):
   - Number of Imported DLLs
   - Number of Imported Functions
   - Suspicious API Count (weighted)
   - Network API Count
   - File System API Count
   - Registry API Count
   - Process API Count
   - Memory API Count

3. **Entropy Features** (4 features):
   - Overall File Entropy
   - Section Entropy Statistics (Mean, Max)
   - Entropy Standard Deviation

4. **String Features** (6 features):
   - Total String Count
   - Average String Length
   - Suspicious String Count
   - URL String Count
   - IP Address String Count
   - Suspicious Pattern Matches

5. **Resource Features** (4 features):
   - Number of Resources
   - Resource Type Diversity
   - Embedded Executable Indicator
   - Icon Count

6. **Statistical Features** (6 features):
   - Null Byte Percentage
   - Printable Character Percentage
   - File Size Category (normalized)
   - Code Section Percentage
   - Data Section Percentage

**Label Encoding**:
- **Multi-class**: 0=Benign, 1=Trojan, 2=Worm, 3=Ransomware, 4=Rootkit, 5=Backdoor, 6=Spyware, 7=Other
- **Binary**: 0=Benign, 1=Malware

**Dataset Characteristics**:
- **Training Size**: ~50,000 PE files
- **Class Distribution**: Benign: ~40%, Malware: ~60% (reflecting real-world prevalence in VirusTotal)
- **File Size Range**: 1 KB - 50 MB (after filtering)

---

## 6. Summary of Preprocessing Decisions

### 6.1 Key Design Principles

1. **Real-Time Feasibility**: All selected features can be extracted in <100ms per sample, enabling real-time detection in cloud environments.

2. **Scalability**: Feature extraction is parallelizable and does not require cross-sample dependencies (except for aggregated IP features, which use efficient streaming algorithms).

3. **Model Compatibility**: Features are designed to work with:
   - **Random Forest**: Categorical encoding, numerical features, no missing values
   - **Isolation Forest**: Normalized numerical features, outlier-resistant
   - **LSTM**: Temporal sequences with fixed-length windows, normalized values

4. **False Positive Reduction**: 
   - Aggregated features reduce noise from individual samples
   - Statistical features (ratios, entropy) capture patterns rather than absolute values
   - Temporal features distinguish attack patterns from normal variations

### 6.2 Feature Selection Justifications Summary

| Module | Features Included | Features Discarded | Primary Justification |
|--------|------------------|-------------------|----------------------|
| **Network Traffic** | 65 features | ~20 redundant/high-correlation features | Real-time extraction, discriminative power, model compatibility |
| **Web Logs** | 42 features | High-cardinality raw fields, PII | Privacy compliance, overfitting prevention, pattern extraction |
| **Malware** | 38 features | Path/timestamp features, high-dimensional raw sequences | Robustness to obfuscation, intrinsic feature focus |

### 6.3 Data Quality Assurance

1. **Missing Value Strategy**: Median/mode imputation preserves distribution while handling edge cases (e.g., unidirectional flows).

2. **Duplicate Handling**: Removed exact duplicates to prevent bias; temporal duplicates allowed for sequence models.

3. **Class Imbalance**: Addressed through:
   - Stratified sampling for train/validation/test splits
   - Synthetic minority oversampling (SMOTE) for rare attack types (if needed)
   - Class weights in model training (Phase 2, not preprocessing)

4. **Outlier Handling**: 
   - Winsorization (capping at 99th percentile) for extreme values
   - Robust scaling (using median and IQR) for features with outliers

### 6.4 Alignment with Cloud Deployment

1. **Streaming Compatibility**: Features can be computed incrementally (e.g., IP-based aggregations use sliding windows).

2. **Storage Efficiency**: 
   - Categorical features use integer encoding (not one-hot for high cardinality)
   - Numerical features normalized to float32 precision
   - Estimated storage: ~500 bytes per network flow, ~200 bytes per web log, ~150 bytes per malware sample

3. **Processing Latency**: 
   - Network features: ~50ms extraction time
   - Web log features: ~30ms extraction time
   - Malware features: ~80ms extraction time (static analysis)

### 6.5 Preprocessing Pipeline Architecture

```
Raw Data → Validation → Cleaning → Feature Engineering → Feature Selection → Normalization → Final Dataset
   ↓           ↓           ↓              ↓                  ↓                ↓              ↓
Filter      Parse      Impute        Derive            Remove           Scale        Export
Invalid     Format     Missing       Statistics        Redundant        Features     Formats
Records     Logs       Values        Ratios            Correlated       [0,1]        (CSV/Parquet)
```

### 6.6 Validation and Quality Metrics

1. **Feature Quality Metrics**:
   - Mutual Information with target: > 0.01 for included features
   - Variance: > 0.01 (after normalization)
   - Correlation with other features: < 0.90

2. **Dataset Quality Metrics**:
   - Missing value percentage: < 5% per feature
   - Duplicate percentage: < 1% (after removal)
   - Class balance: No class < 1% of dataset (after balancing)

3. **Temporal Consistency**:
   - Train/validation/test splits maintain temporal order (no future data in training)
   - Time-based features validated against known attack timelines

---

## Conclusion

The preprocessing phase establishes a robust foundation for the intelligent threat detection system. By carefully selecting and engineering features that balance discriminative power, computational efficiency, and real-time feasibility, the datasets are optimized for accurate, scalable threat detection in cloud environments. The preprocessing decisions prioritize reduction of false positives, compatibility with diverse machine learning models (Random Forest, Isolation Forest, LSTM), and alignment with cloud-scale deployment constraints.

The final datasets—comprising 65 network traffic features, 42 web log features, and 38 malware binary features—provide comprehensive coverage of attack patterns while maintaining the computational efficiency required for real-time detection. All preprocessing steps are designed to be reproducible, well-documented, and suitable for inclusion in academic project documentation.

