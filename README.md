IoT_threat_attribution/
│
├── data/                 
│   ├── raw/              # raw CSV/JSON IoT logs
│   ├── processed/        # cleaned logs (feature engineered)
│   └── samples/          # synthetic test logs
│
├── src/
│   ├── data_collection/
│   │   ├── log_parser.py   # read CSV/JSON & preprocess
│   │   └── log_generator.py # optional: generate synthetic logs
│   │
│   ├── detection/
│   │   ├── rule_engine.py      # rule-based detection (blacklist IPs, signatures)
│   │   └── anomaly_detection.py # ML/statistical anomaly detection
│   │
│   ├── attribution/
│   │   ├── attacker_profile.py # builds attacker MCP profile
│   │   └── context_chain.py    # constructs attack chains
│   │
│   ├── utils/
│   │   ├── helpers.py        # feature extraction, data transforms
│   │   └── visualization.py  # plots attacker profiles / chains
│   │
│   └── main.py               # runs full pipeline
│
├── tests/
│   ├── test_logs.py          # unit test for log parsing
│   ├── test_detection.py     # detection tests
│   └── test_attribution.py   # attribution tests
│
├── notebooks/                # Jupyter experiments (try ML models)
│
├── requirements.txt          # Python deps (pandas, sklearn, networkx, matplotlib)
└── README.md                 # project doc
