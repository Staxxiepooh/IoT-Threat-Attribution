#!/usr/bin/env python3
"""
IoT Threat Attribution System - Main Entry Point (Updated for New Visualization)
"""

import pandas as pd
import sys
import os
import argparse
from datetime import datetime
import matplotlib.pyplot as plt

# Add src directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from data_collection.log_parser import LogParser
from detection.rule_engine import RuleEngine
from detection.anomaly_detection import AnomalyDetector
from attribution.attacker_profile import AttackerProfiler
from attribution.context_chain import ContextChainBuilder
from utils.helpers import setup_logging, save_results, calculate_metrics
from utils.visualization import ThreatVisualizer


class IoTThreatAttribution:
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = setup_logging()

        # Initialize components
        self.log_parser = LogParser()
        self.rule_engine = RuleEngine()
        self.anomaly_detector = AnomalyDetector()
        self.attacker_profiler = AttackerProfiler()
        self.chain_builder = ContextChainBuilder()
        self.visualizer = ThreatVisualizer()

        # Storage for results
        self.parsed_logs = None
        self.rule_detections = None
        self.anomaly_detections = None
        self.attacker_profiles = None
        self.attack_chains = None

    def run_pipeline(self, input_file, output_dir="results"):
        """Run the complete IoT threat attribution pipeline"""
        self.logger.info("🚀 Starting IoT Threat Attribution Pipeline")

        os.makedirs(output_dir, exist_ok=True)

        try:
            # STEP 1: Parse Logs
            self.logger.info("Step 1: Parsing IoT logs...")
            self.parsed_logs = self.log_parser.parse_logs(input_file)
            if self.parsed_logs is None:
                self.logger.error("❌ Failed to parse logs")
                return False
            self.logger.info(f"Parsed {len(self.parsed_logs)} log entries")
            self.log_parser.validate_logs(self.parsed_logs)
            save_results(self.parsed_logs, f"{output_dir}/parsed_logs.csv")

            # STEP 2: Rule-based Detection
            self.logger.info("Step 2: Applying rule-based detection...")
            self.rule_detections = self.rule_engine.apply_rules(self.parsed_logs)
            self.logger.info(f"Rule-based detections: {len(self.rule_detections)}")
            if not self.rule_detections.empty:
                save_results(self.rule_detections, f"{output_dir}/rule_detections.csv")
                metrics = calculate_metrics(self.rule_detections)
                save_results(metrics, f"{output_dir}/rule_metrics.json", format="json")

            # STEP 3: Anomaly Detection
            self.logger.info("Step 3: Running anomaly detection...")
            anomaly_results = self.anomaly_detector.detect_anomalies_isolation_forest(self.parsed_logs)
            self.anomaly_detections = anomaly_results[anomaly_results["is_anomaly"] == True]
            self.logger.info(f"Anomaly detections: {len(self.anomaly_detections)}")

            if not self.anomaly_detections.empty:
                save_results(self.anomaly_detections, f"{output_dir}/anomaly_detections.csv")

            # Behavioral anomalies
            behavioral_anomalies = self.anomaly_detector.detect_behavioral_anomalies(self.parsed_logs)
            if not behavioral_anomalies.empty:
                save_results(behavioral_anomalies, f"{output_dir}/behavioral_anomalies.csv")

            # STEP 4: Combine Detections
            self.logger.info("Step 4: Combining detection results...")
            all_detections = self._combine_detections()
            self.logger.info(f"Total detections combined: {len(all_detections)}")

            # STEP 5: Attacker Profiling
            self.logger.info("Step 5: Creating attacker profiles...")
            self.attacker_profiles = self.attacker_profiler.create_attacker_profiles(
                all_detections, self.parsed_logs
            )
            self.logger.info(f"Attacker profiles created: {len(self.attacker_profiles)}")
            if not self.attacker_profiles.empty:
                save_results(self.attacker_profiles, f"{output_dir}/attacker_profiles.csv")

            # STEP 6: Build Attack Chains
            self.logger.info("Step 6: Building attack chains...")
            self.attack_chains = self.chain_builder.build_attack_chains(
                self.parsed_logs, all_detections
            )
            self.logger.info(f"Attack chains built: {len(self.attack_chains)}")

            if self.attack_chains:
                save_results(self.attack_chains, f"{output_dir}/attack_chains.json", format="json")

            # STEP 7: Visualization
            self.logger.info("Step 7: Generating visualizations...")
            self._generate_visualizations(output_dir)

            # STEP 8: Summary Report
            self.logger.info("Step 8: Generating summary report...")
            self._generate_summary_report(output_dir)

            self.logger.info("✅ IoT Threat Attribution Pipeline completed successfully!")
            return True

        except Exception as e:
            import traceback
            self.logger.error(f"❌ Pipeline failed: {e}")
            self.logger.error(traceback.format_exc())
            return False

    def _combine_detections(self):
        """Combine rule-based and anomaly detections into one DataFrame"""
        combined = pd.DataFrame()

        if self.rule_detections is not None and not self.rule_detections.empty:
            combined = pd.concat([combined, self.rule_detections], ignore_index=True)

        if self.anomaly_detections is not None and not self.anomaly_detections.empty:
            anomaly_df = self.anomaly_detections.copy()
            anomaly_df["rule_name"] = "anomaly_detection"
            anomaly_df["description"] = "Statistical anomaly detected"
            anomaly_df["severity"] = "medium"
            anomaly_df["evidence"] = anomaly_df.get("anomaly_score", "N/A")

            common_cols = ["rule_name", "description", "severity", "source_ip", "device_id", "timestamp", "evidence"]
            anomaly_df = anomaly_df[[c for c in common_cols if c in anomaly_df.columns]]
            combined = pd.concat([combined, anomaly_df], ignore_index=True)

        return combined

    def _generate_visualizations(self, output_dir):
        """Generate all charts and chain visualizations"""
        try:
            # General detection visualizations
            if self.rule_detections is not None and not self.rule_detections.empty:
                timeline = self.visualizer.plot_detection_timeline(self.rule_detections)
                if timeline:
                    timeline.savefig(f"{output_dir}/detection_timeline.png", dpi=300, bbox_inches="tight")
                    plt.close(timeline)

                freq = self.visualizer.plot_threat_frequency(self.rule_detections)
                if freq:
                    freq.savefig(f"{output_dir}/threat_frequency.png", dpi=300, bbox_inches="tight")
                    plt.close(freq)

                sev = self.visualizer.plot_severity_timeline(self.rule_detections)
                if sev:
                    sev.savefig(f"{output_dir}/severity_timeline.png", dpi=300, bbox_inches="tight")
                    plt.close(sev)

                dist = self.visualizer.plot_threat_distribution(self.rule_detections)
                if dist:
                    dist.savefig(f"{output_dir}/threat_distribution.png", dpi=300, bbox_inches="tight")
                    plt.close(dist)

            if self.attacker_profiles is not None and not self.attacker_profiles.empty:
                prof_fig = self.visualizer.plot_attacker_profiles(self.attacker_profiles)
                if prof_fig:
                    prof_fig.savefig(f"{output_dir}/attacker_profiles.png", dpi=300, bbox_inches="tight")
                    plt.close(prof_fig)

            # Attack Chain Visualizations (new version)
            if self.attack_chains:
                self.logger.info("Generating improved attack chain visualizations per device...")
                self.chain_builder.visualize_chain_improved(self.attack_chains, save_path=output_dir)

            self.logger.info("✅ Visualizations saved successfully!")

        except Exception as e:
            import traceback
            self.logger.warning(f"Visualization generation failed: {e}")
            self.logger.warning(traceback.format_exc())

    def _generate_summary_report(self, output_dir):
        """Generate final summary JSON report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_log_entries": len(self.parsed_logs) if self.parsed_logs is not None else 0,
            "rule_detections": len(self.rule_detections) if self.rule_detections is not None else 0,
            "anomaly_detections": len(self.anomaly_detections) if self.anomaly_detections is not None else 0,
            "attacker_profiles": len(self.attacker_profiles) if self.attacker_profiles is not None else 0,
            "attack_chains": len(self.attack_chains) if self.attack_chains is not None else 0,
        }

        if self.rule_detections is not None and not self.rule_detections.empty:
            report["severity_breakdown"] = self.rule_detections["severity"].value_counts().to_dict()

        if self.attacker_profiles is not None and not self.attacker_profiles.empty:
            report["threat_level_distribution"] = self.attacker_profiles["threat_level"].value_counts().to_dict()
            report["skill_level_distribution"] = self.attacker_profiles["skill_level"].value_counts().to_dict()

        if self.attack_chains:
            device_chains = {}
            for chain in self.attack_chains:
                dev = chain.get("device_id", "unknown")
                device_chains[dev] = device_chains.get(dev, 0) + 1
            report["attack_chains_by_device"] = device_chains

        save_results(report, f"{output_dir}/summary_report.json", format="json")

        print("\n" + "=" * 60)
        print("📊 IoT THREAT ATTRIBUTION SUMMARY")
        print("=" * 60)
        for k, v in report.items():
            print(f"{k}: {v}")
        print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description="IoT Threat Attribution System")
    parser.add_argument("--input", "-i", required=True, help="Input log file (CSV/JSON)")
    parser.add_argument("--output", "-o", default="results", help="Output directory")
    parser.add_argument("--device", "-d", help="Specific device ID to analyze")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"❌ Error: Input file '{args.input}' not found.")
        sys.exit(1)

    threat_system = IoTThreatAttribution()
    success = threat_system.run_pipeline(args.input, args.output)

    if success:
        print(f"\n✅ Pipeline completed! Results saved to '{args.output}'")
        sys.exit(0)
    else:
        print("\n❌ Pipeline failed. Check logs for details.")
        sys.exit(1)


if __name__ == "__main__":
    main()
