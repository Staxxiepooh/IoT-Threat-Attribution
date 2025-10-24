#!/usr/bin/env python3
"""
IoT Threat Attribution System - Main Entry Point
"""

import pandas as pd
import sys
import os
import argparse
from datetime import datetime

# Add the src directory to Python path
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
        
        # Results storage
        self.parsed_logs = None
        self.rule_detections = None
        self.anomaly_detections = None
        self.attacker_profiles = None
        self.attack_chains = None
        
    def run_pipeline(self, input_file, output_dir="results"):
        """Run the complete threat attribution pipeline"""
        self.logger.info("Starting IoT Threat Attribution Pipeline")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            # Step 1: Data Collection and Parsing
            self.logger.info("Step 1: Parsing IoT logs...")
            self.parsed_logs = self.log_parser.parse_logs(input_file)
            
            if self.parsed_logs is None:
                self.logger.error("Failed to parse logs")
                return False
                
            self.logger.info(f"Parsed {len(self.parsed_logs)} log entries")
            
            # Validate logs
            self.log_parser.validate_logs(self.parsed_logs)
            
            # Save parsed data
            save_results(self.parsed_logs, f"{output_dir}/parsed_logs.csv")
            
            # Step 2: Rule-based Detection
            self.logger.info("Step 2: Running rule-based detection...")
            self.rule_detections = self.rule_engine.apply_rules(self.parsed_logs)
            self.logger.info(f"Rule-based detections: {len(self.rule_detections)}")
            
            if not self.rule_detections.empty:
                save_results(self.rule_detections, f"{output_dir}/rule_detections.csv")
                
                # Calculate metrics
                rule_metrics = calculate_metrics(self.rule_detections)
                save_results(rule_metrics, f"{output_dir}/rule_metrics.json", format='json')
                self.logger.info(f"Rule detection metrics: {rule_metrics}")
            
            # Step 3: Anomaly Detection
            self.logger.info("Step 3: Running anomaly detection...")
            anomaly_results = self.anomaly_detector.detect_anomalies_isolation_forest(self.parsed_logs)
            
            # Extract anomaly events
            self.anomaly_detections = anomaly_results[anomaly_results['is_anomaly'] == True]
            self.logger.info(f"Anomaly detections: {len(self.anomaly_detections)}")
            
            if not self.anomaly_detections.empty:
                save_results(self.anomaly_detections, f"{output_dir}/anomaly_detections.csv")
            
            # Behavioral anomalies
            behavioral_anomalies = self.anomaly_detector.detect_behavioral_anomalies(self.parsed_logs)
            self.logger.info(f"Behavioral anomalies: {len(behavioral_anomalies)}")
            
            if not behavioral_anomalies.empty:
                save_results(behavioral_anomalies, f"{output_dir}/behavioral_anomalies.csv")
            
            # Step 4: Combine detections
            self.logger.info("Step 4: Combining detection results...")
            all_detections = self._combine_detections()
            self.logger.info(f"Total unique detections: {len(all_detections)}")
            
            # Step 5: Attacker Profiling
            self.logger.info("Step 5: Building attacker profiles...")
            self.attacker_profiles = self.attacker_profiler.create_attacker_profiles(
                all_detections, self.parsed_logs
            )
            self.logger.info(f"Created {len(self.attacker_profiles)} attacker profiles")
            
            if not self.attacker_profiles.empty:
                save_results(self.attacker_profiles, f"{output_dir}/attacker_profiles.csv")
            
            # Step 6: Attack Chain Analysis
            self.logger.info("Step 6: Building attack chains...")
            self.attack_chains = self.chain_builder.build_attack_chains(
                self.parsed_logs, all_detections
            )
            self.logger.info(f"Built {len(self.attack_chains)} attack chains")
            
            if self.attack_chains:
                save_results(self.attack_chains, f"{output_dir}/attack_chains.json", format='json')
                
                # Display first chain
                if self.attack_chains:
                    chain_viz = self.chain_builder.visualize_chain(self.attack_chains[0])
                    self.logger.info(f"Sample attack chain:\n{chain_viz}")
            
            # Step 7: Generate Visualizations
            self.logger.info("Step 7: Generating visualizations...")
            self._generate_visualizations(output_dir)
            
            # Step 8: Generate Summary Report
            self.logger.info("Step 8: Generating summary report...")
            self._generate_summary_report(output_dir)
            
            self.logger.info("IoT Threat Attribution Pipeline completed successfully!")
            return True
            
        except Exception as e:
            self.logger.error(f"Pipeline failed: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            return False
    
    def _combine_detections(self):
        """Combine rule-based and anomaly detections"""
        all_detections = pd.DataFrame()
        
        # Add rule-based detections
        if self.rule_detections is not None and not self.rule_detections.empty:
            all_detections = pd.concat([all_detections, self.rule_detections], ignore_index=True)
        
        # Add anomaly detections with proper formatting
        if self.anomaly_detections is not None and not self.anomaly_detections.empty:
            anomaly_df = self.anomaly_detections.copy()
            anomaly_df['rule_name'] = 'anomaly_detection'
            anomaly_df['description'] = 'Statistical anomaly detected'
            anomaly_df['severity'] = 'medium'  # Default severity for anomalies
            anomaly_df['evidence'] = f"Anomaly score: {anomaly_df.get('anomaly_score', 'N/A')}"
            
            # Select only relevant columns for consistency
            common_columns = ['rule_name', 'description', 'severity', 'source_ip', 'device_id', 'timestamp', 'evidence']
            available_columns = [col for col in common_columns if col in anomaly_df.columns]
            
            all_detections = pd.concat([
                all_detections, 
                anomaly_df[available_columns]
            ], ignore_index=True)
        
        return all_detections
    
    def _generate_visualizations(self, output_dir):
        """Generate various visualizations"""
        try:
            import matplotlib.pyplot as plt
            
            # Timeline visualization
            if self.rule_detections is not None and not self.rule_detections.empty:
                # Multiple timeline visualizations
                timeline_fig = self.visualizer.plot_detection_timeline(self.rule_detections)
                if timeline_fig:
                    timeline_fig.savefig(f"{output_dir}/detection_timeline.png", dpi=300, bbox_inches='tight')
                    plt.close(timeline_fig)
                
                # Threat frequency plot
                frequency_fig = self.visualizer.plot_threat_frequency(self.rule_detections)
                if frequency_fig:
                    frequency_fig.savefig(f"{output_dir}/threat_frequency.png", dpi=300, bbox_inches='tight')
                    plt.close(frequency_fig)
                
                # Severity timeline
                severity_fig = self.visualizer.plot_severity_timeline(self.rule_detections)
                if severity_fig:
                    severity_fig.savefig(f"{output_dir}/severity_timeline.png", dpi=300, bbox_inches='tight')
                    plt.close(severity_fig)
            
            # Attacker profiles visualization
            if self.attacker_profiles is not None and not self.attacker_profiles.empty:
                profile_fig = self.visualizer.plot_attacker_profiles(self.attacker_profiles)
                if profile_fig:
                    profile_fig.savefig(f"{output_dir}/attacker_profiles.png", dpi=300, bbox_inches='tight')
                    plt.close(profile_fig)
            
            # Threat distribution
            if self.rule_detections is not None and not self.rule_detections.empty:
                threat_fig = self.visualizer.plot_threat_distribution(self.rule_detections)
                if threat_fig:
                    threat_fig.savefig(f"{output_dir}/threat_distribution.png", dpi=300, bbox_inches='tight')
                    plt.close(threat_fig)
                    
            self.logger.info("Visualizations saved successfully")
            
        except Exception as e:
            self.logger.warning(f"Visualization generation failed: {e}")
            import traceback
            self.logger.warning(f"Traceback: {traceback.format_exc()}")
    
    def _generate_summary_report(self, output_dir):
        """Generate a summary report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_log_entries": len(self.parsed_logs) if self.parsed_logs is not None else 0,
            "rule_detections": len(self.rule_detections) if self.rule_detections is not None else 0,
            "anomaly_detections": len(self.anomaly_detections) if self.anomaly_detections is not None else 0,
            "attacker_profiles": len(self.attacker_profiles) if self.attacker_profiles is not None else 0,
            "attack_chains": len(self.attack_chains) if self.attack_chains is not None else 0,
        }
        
        # Add severity breakdown
        if self.rule_detections is not None and not self.rule_detections.empty:
            severity_counts = self.rule_detections['severity'].value_counts().to_dict()
            report["severity_breakdown"] = severity_counts
        
        # Add attacker profile summary
        if self.attacker_profiles is not None and not self.attacker_profiles.empty:
            report["threat_level_distribution"] = self.attacker_profiles['threat_level'].value_counts().to_dict()
            report["skill_level_distribution"] = self.attacker_profiles['skill_level'].value_counts().to_dict()
        
        save_results(report, f"{output_dir}/summary_report.json", format='json')
        
        # Print summary to console
        print("\n" + "="*50)
        print("IoT THREAT ATTRIBUTION SUMMARY")
        print("="*50)
        print(f"Total Log Entries: {report['total_log_entries']}")
        print(f"Rule-based Detections: {report['rule_detections']}")
        print(f"Anomaly Detections: {report['anomaly_detections']}")
        print(f"Attacker Profiles: {report['attacker_profiles']}")
        print(f"Attack Chains Identified: {report['attack_chains']}")
        
        if 'severity_breakdown' in report:
            print(f"Severity Breakdown: {report['severity_breakdown']}")
        
        if 'threat_level_distribution' in report:
            print(f"Threat Level Distribution: {report['threat_level_distribution']}")
        
        print("="*50)

def main():
    """Main function with command line interface"""
    parser = argparse.ArgumentParser(description='IoT Threat Attribution System')
    parser.add_argument('--input', '-i', required=True, 
                       help='Input log file path (CSV or JSON)')
    parser.add_argument('--output', '-o', default='results',
                       help='Output directory for results (default: results)')
    parser.add_argument('--config', '-c', 
                       help='Configuration file path')
    
    args = parser.parse_args()
    
    # Check if input file exists
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found")
        sys.exit(1)
    
    # Initialize and run the system
    threat_system = IoTThreatAttribution()
    
    success = threat_system.run_pipeline(
        input_file=args.input,
        output_dir=args.output
    )
    
    if success:
        print(f"\nPipeline completed successfully! Results saved to '{args.output}' directory")
        sys.exit(0)
    else:
        print("\nPipeline failed! Check logs for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()