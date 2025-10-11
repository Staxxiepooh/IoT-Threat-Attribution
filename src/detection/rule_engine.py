import pandas as pd
import re
from datetime import datetime, timedelta

class RuleEngine:
    def __init__(self):
        self.rules = self._initialize_rules()
    
    def _initialize_rules(self):
        """Initialize detection rules"""
        rules = {
            'brute_force_attempt': {
                'description': 'Multiple failed authentication attempts from same source',
                'threshold': 5,
                'time_window_minutes': 10
            },
            'data_exfiltration': {
                'description': 'Large data transfer to external IP',
                'payload_threshold': 5000,
                'external_ip': True
            },
            'malicious_ip': {
                'description': 'Connection from known malicious IP',
                'malicious_ips': ['10.0.0.50', '192.168.1.200']  # Example malicious IPs
            },
            'suspicious_protocol': {
                'description': 'Unusual protocol usage for device type',
                'suspicious_combinations': [
                    {'device_prefix': 'sensor', 'protocol': 'TCP', 'port': '80'},
                    {'device_prefix': 'camera', 'protocol': 'UDP', 'port': '53'}
                ]
            }
        }
        return rules
    
    def apply_rules(self, df):
        """Apply all rules to the dataset"""
        results = []
        
        # Apply each rule
        results.extend(self.detect_brute_force(df))
        results.extend(self.detect_data_exfiltration(df))
        results.extend(self.detect_malicious_ips(df))
        results.extend(self.detect_suspicious_protocols(df))
        
        return pd.DataFrame(results)
    
    def detect_brute_force(self, df):
        """Detect brute force attacks"""
        results = []
        rule = self.rules['brute_force_attempt']
        
        # Filter authentication events
        auth_events = df[df['event_type'].str.contains('auth', case=False, na=False)]
        
        # Group by source IP and time window
        time_window = timedelta(minutes=rule['time_window_minutes'])
        
        for source_ip in auth_events['source_ip'].unique():
            ip_events = auth_events[auth_events['source_ip'] == source_ip]
            ip_events = ip_events.sort_values('timestamp')
            
            # Simple detection: count events in recent period
            recent_count = len(ip_events)
            
            if recent_count >= rule['threshold']:
                results.append({
                    'rule_name': 'brute_force_attempt',
                    'description': rule['description'],
                    'severity': 'high',
                    'source_ip': source_ip,
                    'device_id': ip_events['device_id'].iloc[0],
                    'timestamp': ip_events['timestamp'].iloc[-1],
                    'evidence': f'{recent_count} authentication attempts from {source_ip}'
                })
        
        return results
    
    def detect_data_exfiltration(self, df):
        """Detect potential data exfiltration"""
        results = []
        rule = self.rules['data_exfiltration']
        
        # Filter data transfer events to external IPs
        external_transfers = df[
            (df['event_type'].str.contains('data', case=False, na=False)) &
            (df.get('source_ip_type', 'internal') == 'internal') &
            (df.get('payload_size', 0) > rule['payload_threshold'])
        ]
        
        for _, event in external_transfers.iterrows():
            results.append({
                'rule_name': 'data_exfiltration',
                'description': rule['description'],
                'severity': 'high',
                'source_ip': event['source_ip'],
                'device_id': event['device_id'],
                'timestamp': event['timestamp'],
                'evidence': f'Large data transfer ({event.get("payload_size", 0)} bytes) to external IP'
            })
        
        return results
    
    def detect_malicious_ips(self, df):
        """Detect connections from known malicious IPs"""
        results = []
        rule = self.rules['malicious_ip']
        
        malicious_ips = rule['malicious_ips']
        
        for malicious_ip in malicious_ips:
            malicious_events = df[df['source_ip'] == malicious_ip]
            
            for _, event in malicious_events.iterrows():
                results.append({
                    'rule_name': 'malicious_ip',
                    'description': rule['description'],
                    'severity': 'critical',
                    'source_ip': event['source_ip'],
                    'device_id': event['device_id'],
                    'timestamp': event['timestamp'],
                    'evidence': f'Connection from known malicious IP: {malicious_ip}'
                })
        
        return results
    
    def detect_suspicious_protocols(self, df):
        """Detect suspicious protocol usage"""
        results = []
        
        # Simple pattern matching for device types
        for _, event in df.iterrows():
            device_id = event['device_id']
            protocol = event.get('protocol', '')
            
            if 'sensor' in device_id and protocol == 'TCP':
                results.append({
                    'rule_name': 'suspicious_protocol',
                    'description': 'Unusual TCP protocol usage for sensor device',
                    'severity': 'medium',
                    'source_ip': event['source_ip'],
                    'device_id': event['device_id'],
                    'timestamp': event['timestamp'],
                    'evidence': f'Sensor device using TCP protocol'
                })
        
        return results

# Example usage
if __name__ == "__main__":
    from data_collection.log_parser import LogParser
    
    parser = LogParser()
    df = parser.parse_logs('../../../data/raw/sample_iot_logs.csv')
    
    rule_engine = RuleEngine()
    results = rule_engine.apply_rules(df)
    print("Rule-based detection results:")
    print(results)