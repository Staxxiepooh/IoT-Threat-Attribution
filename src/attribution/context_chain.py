import pandas as pd
import networkx as nx
from datetime import datetime, timedelta

class ContextChainBuilder:
    def __init__(self):
        self.attack_chains = []
    
    def build_attack_chains(self, log_data, detection_results, time_window_minutes=30):
        """Build attack chains from correlated events"""
        chains = []
        
        # Sort data by timestamp
        log_data = log_data.sort_values('timestamp')
        detection_results = detection_results.sort_values('timestamp')
        
        # Group events by time windows and source IPs
        source_ips = detection_results['source_ip'].unique()
        
        for source_ip in source_ips:
            ip_detections = detection_results[detection_results['source_ip'] == source_ip]
            ip_events = log_data[log_data['source_ip'] == source_ip]
            
            if not ip_detections.empty:
                chains.extend(
                    self._build_ip_attack_chain(source_ip, ip_detections, ip_events, time_window_minutes)
                )
        
        return chains
    
    def _build_ip_attack_chain(self, source_ip, detections, events, time_window_minutes):
        """Build attack chain for a specific IP"""
        chains = []
        
        # Create time-based groups of detections
        time_window = timedelta(minutes=time_window_minutes)
        
        detection_groups = []
        current_group = []
        
        for _, detection in detections.iterrows():
            if not current_group:
                current_group.append(detection)
            else:
                time_diff = detection['timestamp'] - current_group[-1]['timestamp']
                if time_diff <= time_window:
                    current_group.append(detection)
                else:
                    detection_groups.append(current_group)
                    current_group = [detection]
        
        if current_group:
            detection_groups.append(current_group)
        
        # Build chains from groups
        for group in detection_groups:
            if len(group) > 1:  # Only create chains with multiple detections
                chain = self._create_chain_from_group(source_ip, group, events)
                if chain:
                    chains.append(chain)
        
        return chains
    
    def _create_chain_from_group(self, source_ip, detection_group, events):
        """Create a single attack chain from a detection group"""
        if not detection_group:
            return None
        
        # Get relevant events around detection times
        start_time = detection_group[0]['timestamp'] - timedelta(minutes=5)
        end_time = detection_group[-1]['timestamp'] + timedelta(minutes=5)
        
        relevant_events = events[
            (events['timestamp'] >= start_time) & 
            (events['timestamp'] <= end_time)
        ]
        
        # Build chain structure
        chain = {
            'chain_id': f"chain_{source_ip}_{start_time.strftime('%Y%m%d_%H%M%S')}",
            'source_ip': source_ip,
            'start_time': start_time,
            'end_time': end_time,
            'duration_minutes': (end_time - start_time).total_seconds() / 60,
            'detection_count': len(detection_group),
            'attack_types': [det['rule_name'] for det in detection_group],
            'max_severity': max(det['severity'] for det in detection_group),
            'events_sequence': [],
            'tactics_identified': self._identify_attack_tactics(detection_group),
            'confidence_score': self._calculate_chain_confidence(detection_group, relevant_events)
        }
        
        # Add event sequence
        all_events = pd.concat([relevant_events, pd.DataFrame(detection_group)])
        all_events = all_events.sort_values('timestamp')
        
        chain['events_sequence'] = all_events.to_dict('records')
        
        return chain
    
    def _identify_attack_tactics(self, detection_group):
        """Identify MITRE ATT&CK like tactics from detections"""
        tactics = set()
        
        tactic_mapping = {
            'brute_force_attempt': 'Credential Access',
            'data_exfiltration': 'Exfiltration',
            'malicious_ip': 'Initial Access',
            'suspicious_protocol': 'Command and Control'
        }
        
        for detection in detection_group:
            rule_name = detection['rule_name']
            if rule_name in tactic_mapping:
                tactics.add(tactic_mapping[rule_name])
        
        return list(tactics)
    
    def _calculate_chain_confidence(self, detection_group, relevant_events):
        """Calculate confidence score for the attack chain"""
        confidence = 0.0
        
        # More detections increase confidence
        confidence += min(0.4, len(detection_group) * 0.1)
        
        # Supporting events increase confidence
        if len(relevant_events) > len(detection_group):
            confidence += 0.3
        
        # Multiple attack types increase confidence
        attack_types = set(det['rule_name'] for det in detection_group)
        if len(attack_types) > 1:
            confidence += 0.2
        
        # High severity events increase confidence
        severities = [det['severity'] for det in detection_group]
        if 'critical' in severities or 'high' in severities:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def visualize_chain(self, chain):
        """Create a simple text visualization of attack chain"""
        if not chain:
            return "No chain to visualize"
        
        visualization = f"""
Attack Chain: {chain['chain_id']}
Source IP: {chain['source_ip']}
Time Range: {chain['start_time']} to {chain['end_time']}
Duration: {chain['duration_minutes']:.1f} minutes
Detections: {chain['detection_count']}
Tactics: {', '.join(chain['tactics_identified'])}
Confidence: {chain['confidence_score']:.2f}

Event Sequence:
"""
        
        for i, event in enumerate(chain['events_sequence'][:10]):  # Show first 10 events
            visualization += f"{i+1}. {event.get('timestamp', '')} - {event.get('event_type', '')} - {event.get('rule_name', 'log')}\n"
        
        return visualization

# Example usage
if __name__ == "__main__":
    from data_collection.log_parser import LogParser
    from detection.rule_engine import RuleEngine
    
    parser = LogParser()
    df = parser.parse_logs('../../../data/raw/sample_iot_logs.csv')
    
    rule_engine = RuleEngine()
    detections = rule_engine.apply_rules(df)
    
    chain_builder = ContextChainBuilder()
    chains = chain_builder.build_attack_chains(df, detections)
    
    print(f"Built {len(chains)} attack chains")
    if chains:
        print(chain_builder.visualize_chain(chains[0]))