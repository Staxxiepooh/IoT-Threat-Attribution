🛰️ IoT Threat Attribution using Context Chains & MCP

An intelligent system for detecting, analyzing, and attributing IoT-based cyber threats using a hybrid of rule-based and ML-based strategies.








📘 Overview

IoT Threat Attribution is a modular project designed to detect and attribute malicious activities in IoT environments.
It combines rule-based detection (using blacklists and known attack patterns) with machine learning (statistical anomaly detection) to form a hybrid security framework.

The project simulates data ingestion, detection, and attribution using local CSV datasets — ideal for research, visualization, and experimentation.

⚙️ Project Architecture
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
│   │   ├── rule_engine.py      # Rule-based detection (blacklists, signatures)
│   │   └── anomaly_detection.py # ML/statistical anomaly detection
│   │
│   ├── attribution/          # Threat attribution layer
│   │   ├── attacker_profile.py # Build attacker profiles (MCP)
│   │   └── context_chain.py    # Construct attack chains over time
│   │
│   ├── utils/                # Helper utilities
│   │   ├── helpers.py          # Feature extraction & data transformations
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
├── requirements.txt          # Dependencies
└── README.md                 # Project documentation

🧠 Core Features
Module	Description
Rule-Based Detection	Detect known malicious IPs, patterns, and signatures.
Anomaly Detection (ML)	Uses statistical models (Isolation Forest, etc.) to detect outliers.
Attribution Engine	Links alerts to attacker profiles using MCP context.
Context Chains	Reconstructs multi-step attacks over time.
Visualization	Network graphs and timeline-based visualizations of attacker activity.
🚀 Getting Started
1️⃣ Clone the Repository
git clone https://github.com/IndrayudhMukherjee/IOT-THREAT-ATTRIBUTION-UPDATED.git
cd IOT-THREAT-ATTRIBUTION-UPDATED

2️⃣ Create Virtual Environment (Recommended)
python3 -m venv .venv
source .venv/bin/activate

3️⃣ Install Dependencies
pip install -r requirements.txt

4️⃣ Run the Pipeline
python3 -m src.main


This will:

Load IoT data from data/raw/sample_iot_logs.csv

Run both rule-based and ML anomaly detection

Save combined results in data/processed/processed_logs.csv

📊 Example Output

Sample processed output (stored in data/processed/processed_logs.csv):

timestamp	device_id	event_type	threat_detected	detection_type
2024-01-01 10:00:30	device_001	malware_detected	✅	Rule-based
2024-01-01 10:00:35	device_003	brute_force	✅	Rule-based
2024-01-01 10:00:40	device_005	data_exfiltration	✅	ML-based
🧩 Tech Stack

Python 3.9+

Pandas, Scikit-learn — Data preprocessing & ML

NetworkX, Matplotlib — Visualization & graph construction

JSON/CSV — Data formats

VS Code + macOS M1 — Development environment

📚 Future Scope

Integration with real-time MQTT feeds

Advanced ML: Autoencoders, LSTM-based sequence anomaly detection

Real-world MCP Integration (AWS IoT Core, Azure IoT Hub)

Web dashboard for threat visualization

👨‍💻 Author

Indrayudh Mukherjee
📍 B.Tech CSE | KIIT University
💼 Data, AI & Security Enthusiast
🌐 GitHub Profile

📜 License

This project is licensed under the MIT License — free for personal and academic use.
