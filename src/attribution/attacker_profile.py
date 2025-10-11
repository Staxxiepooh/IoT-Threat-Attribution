import pandas as pd
import numpy as np
from datetime import datetime, timedelta

class AttackerProfiler:
    def __init__(self):
        self.profiles = {}
    
    def create_attacker_profiles(self, detection_results, log_data):
        """Create attacker profiles from detection results"""
        profiles = []
        
        # Group detections by source IP
        source_ip_groups = detection_results.groupby('source_ip')
        
        for source_ip, group in source_ip_groups:
            profile = self._build_individual_profile(source_ip, group, log_data)
            if profile:
                profiles.append(profile)
        
        return pd.DataFrame(profiles)
    
    def _build_individual_profile(self, source_ip, detections, log_data):
        """Build individual attacker profile"""
        if detections.empty:
            return None
        
        # Get all events from this source IP
        ip_events = log_data[log_data['source_ip'] == source_ip]
        
        if ip_events.empty:
            return None
        
        # Calculate profile attributes
        first_seen = ip_events['timestamp'].min()
        last_seen = ip_events['timestamp'].max()
        duration_hours = (last_seen - first_seen).total_seconds() / 3600
        
        # Attack characteristics
        attack_types = detections['rule_name'].unique().tolist()
        max_severity = detections['severity'].max()
        
        # Target analysis
        target_devices = ip_events['device_id'].unique().tolist()
        
        # Behavioral patterns
        event_frequency = len(ip_events) / max(1, duration_hours)  # events per hour
        
        # Skill level estimation
        skill_level = self._estimate_skill_level(detections, ip_events)
        
        # Motivation estimation
        motivation = self._estimate_motivation(detections, ip_events)
        
        profile = {
            'source_ip': source_ip,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'duration_hours': duration_hours,
            'total_events': len(ip_events),
            'event_frequency': event_frequency,
            'attack_types': attack_types,
            'num_attack_types': len(attack_types),
            'max_severity': max_severity,
            'target_devices': target_devices,
            'num_targets': len(target_devices),
            'skill_level': skill_level,
            'motivation': motivation,
            'threat_level': self._calculate_threat_level(skill_level, motivation, max_severity),
            'profile_confidence': self._calculate_confidence(detections, ip_events)
        }
        
        return profile
    
    def _estimate_skill_level(self, detections, ip_events):
        """Estimate attacker skill level"""
        score = 0
        
        # Factors increasing skill level
        if len(detections) > 1:
            score += 1
        
        if 'data_exfiltration' in detections['rule_name'].values:
            score += 2
        
        if 'brute_force_attempt' in detections['rule_name'].values:
            score += 1
        
        # Duration of activity
        duration = (ip_events['timestamp'].max() - ip_events['timestamp'].min()).total_seconds() / 3600
        if duration > 1:  # More than 1 hour
            score += 1
        
        # Map score to skill levels
        if score >= 4:
            return 'advanced'
        elif score >= 2:
            return 'intermediate'
        else:
            return 'beginner'
    
    def _estimate_motivation(self, detections, ip_events):
        """Estimate attacker motivation"""
        motivations = []
        
        # Analyze attack patterns for motivation clues
        if 'data_exfiltration' in detections['rule_name'].values:
            motivations.append('data_theft')
        
        if 'brute_force_attempt' in detections['rule_name'].values:
            motivations.append('unauthorized_access')
        
        if len(ip_events) > 10:  # High activity
            motivations.append('persistent_attack')
        
        # Return primary motivation or unknown
        return motivations[0] if motivations else 'unknown'
    
    def _calculate_threat_level(self, skill_level, motivation, max_severity):
        """Calculate overall threat level"""
        threat_score = 0
        
        # Skill level weighting
        skill_weights = {'beginner': 1, 'intermediate': 2, 'advanced': 3}
        threat_score += skill_weights.get(skill_level, 1)
        
        # Motivation weighting
        motivation_weights = {
            'unknown': 1,
            'unauthorized_access': 2,
            'data_theft': 3,
            'persistent_attack': 2
        }
        threat_score += motivation_weights.get(motivation, 1)
        
        # Severity weighting
        severity_weights = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        threat_score += severity_weights.get(max_severity, 1)
        
        # Map to threat levels
        if threat_score >= 8:
            return 'critical'
        elif threat_score >= 6:
            return 'high'
        elif threat_score >= 4:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_confidence(self, detections, ip_events):
        """Calculate confidence score for the profile"""
        confidence = 0.5  # Base confidence
        
        # More detections increase confidence
        confidence += min(0.3, len(detections) * 0.1)
        
        # More events increase confidence
        confidence += min(0.2, len(ip_events) * 0.01)
        
        return min(confidence, 1.0)  # Cap at 1.0

# Example usage
if __name__ == "__main__":
    from data_collection.log_parser import LogParser
    from detection.rule_engine import RuleEngine
    
    parser = LogParser()
    df = parser.parse_logs('../../../data/raw/sample_iot_logs.csv')
    
    rule_engine = RuleEngine()
    detections = rule_engine.apply_rules(df)
    
    profiler = AttackerProfiler()
    profiles = profiler.create_attacker_profiles(detections, df)
    
    print("Attacker profiles:")
    print(profiles)