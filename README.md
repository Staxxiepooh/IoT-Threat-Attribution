📂 IoT Threat Attribution

This repository implements a hybrid IoT threat attribution pipeline using rule-based detection + ML anomaly detection, followed by MCP (Multi-Context Profiling) and Context Chains for attacker attribution.

📁 Project Structure
IoT_threat_attribution/
│
├── data/                     # Datasets
│   ├── raw/                  # Raw IoT logs (CSV/JSON)
│   ├── processed/             # Cleaned & feature-engineered logs
│   └── samples/               # Synthetic / test logs
│
├── src/                      # Source code
│   ├── data_collection/      # Data ingestion & generation
│   │   ├── log_parser.py       # Load & preprocess CSV/JSON logs
│   │   └── log_generator.py    # Generate synthetic IoT logs
│   │
│   ├── detection/            # Threat detection layer
│   │   ├── rule_engine.py      # Rule-based detection (blacklists, signatures, thresholds)
│   │   └── anomaly_detection.py # ML/statistical anomaly detection (e.g. Isolation Forest)
│   │
│   ├── attribution/          # Threat attribution layer
│   │   ├── attacker_profile.py # Build attacker profiles (MCP)
│   │   └── context_chain.py    # Construct attack chains over time
│   │
│   ├── utils/                # Helper utilities
│   │   ├── helpers.py          # Feature extraction & transformations
│   │   └── visualization.py    # Visualize attacker profiles & chains
│   │
│   └── main.py               # Orchestration: runs full pipeline
│
├── tests/                    # Unit tests
│   ├── test_logs.py            # Test log parsing
│   ├── test_detection.py       # Test detection modules
│   └── test_attribution.py     # Test attribution modules
│
├── notebooks/                # Jupyter experiments (ML prototyping)
│
├── requirements.txt          # Dependencies (pandas, sklearn, matplotlib, networkx, etc.)
└── README.md                 # Project documentation

🔹 Pipeline Overview

Data Collection → Ingest IoT logs (CSV/JSON).

Detection Layer

Rule Engine: blacklist, regex signatures, thresholds.

ML Anomaly Detection: e.g., Isolation Forest, One-Class SVM.

Attribution Layer

MCP: build attacker profiles across contexts (network, device, temporal, attack).

Context Chains: connect sequential attack events into an attack path.

Visualization → Graphs of attack chains & attacker profiles.

⚡ Tech Stack

Python: core implementation

Pandas / Numpy: data handling

Scikit-learn: anomaly detection (ML)

NetworkX: context chain graphs

Matplotlib / Seaborn: visualization
