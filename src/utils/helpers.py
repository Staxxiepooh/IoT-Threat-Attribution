import pandas as pd
import numpy as np
import json
from datetime import datetime
import logging

def setup_logging(log_file='iot_threat_attribution.log'):
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def save_results(results, filename, format='csv'):
    """Save results to file in specified format"""
    try:
        if format.lower() == 'csv':
            if isinstance(results, pd.DataFrame):
                results.to_csv(filename, index=False)
            else:
                pd.DataFrame(results).to_csv(filename, index=False)
        
        elif format.lower() == 'json':
            with open(filename, 'w') as f:
                if isinstance(results, pd.DataFrame):
                    json.dump(results.to_dict('records'), f, indent=2, default=str)
                else:
                    json.dump(results, f, indent=2, default=str)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        print(f"Results saved to {filename}")
        
    except Exception as e:
        print(f"Error saving results: {e}")

def load_results(filename):
    """Load results from file"""
    try:
        if filename.endswith('.csv'):
            return pd.read_csv(filename)
        elif filename.endswith('.json'):
            with open(filename, 'r') as f:
                return json.load(f)
        else:
            raise ValueError("Unsupported file format")
    except Exception as e:
        print(f"Error loading results: {e}")
        return None

def calculate_metrics(detection_results, ground_truth=None):
    """Calculate detection performance metrics"""
    metrics = {}
    
    if detection_results.empty:
        return metrics
    
    # Basic counts
    metrics['total_detections'] = len(detection_results)
    metrics['unique_attackers'] = detection_results['source_ip'].nunique()
    
    # Severity distribution
    severity_counts = detection_results['severity'].value_counts().to_dict()
    metrics['severity_distribution'] = severity_counts
    
    # Attack type distribution
    attack_type_counts = detection_results['rule_name'].value_counts().to_dict()
    metrics['attack_type_distribution'] = attack_type_counts
    
    # Temporal metrics
    if 'timestamp' in detection_results.columns:
        time_range = detection_results['timestamp'].max() - detection_results['timestamp'].min()
        metrics['detection_time_range_hours'] = time_range.total_seconds() / 3600
        metrics['detection_rate_per_hour'] = metrics['total_detections'] / max(1, metrics['detection_time_range_hours'])
    
    return metrics

def validate_config(config):
    """Validate configuration parameters"""
    required_fields = ['input_path', 'output_dir']
    
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required config field: {field}")
    
    return True

def format_timestamp(timestamp):
    """Format timestamp consistently"""
    if isinstance(timestamp, str):
        return pd.to_datetime(timestamp)
    elif isinstance(timestamp, datetime):
        return timestamp
    else:
        return pd.to_datetime(timestamp)

# Example usage
if __name__ == "__main__":
    logger = setup_logging()
    logger.info("Helper functions loaded successfully")
    
    # Test metrics calculation
    sample_data = pd.DataFrame({
        'source_ip': ['192.168.1.1', '192.168.1.2', '192.168.1.1'],
        'severity': ['high', 'medium', 'high'],
        'rule_name': ['rule1', 'rule2', 'rule1'],
        'timestamp': [datetime.now()] * 3
    })
    
    metrics = calculate_metrics(sample_data)
    print("Sample metrics:", metrics)