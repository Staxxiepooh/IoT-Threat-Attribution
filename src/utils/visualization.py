import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from datetime import datetime
import networkx as nx

class ThreatVisualizer:
    def __init__(self, style='darkgrid'):
        self.style = style
        sns.set_style(style)
        plt.rcParams['figure.figsize'] = [12, 8]
    
    def plot_detection_timeline(self, detection_results, time_column='timestamp'):
        """Plot detection events timeline"""
        if detection_results.empty:
            print("No data to plot")
            return None
        
        fig, ax = plt.subplots(figsize=(15, 8))
        
        # Convert to datetime if needed
        detection_results[time_column] = pd.to_datetime(detection_results[time_column])
        
        # Create timeline plot
        severity_colors = {'low': 'green', 'medium': 'orange', 'high': 'red', 'critical': 'purple'}
        
        for severity, color in severity_colors.items():
            severity_data = detection_results[detection_results['severity'] == severity]
            if not severity_data.empty:
                ax.scatter(
                    severity_data[time_column],
                    [severity] * len(severity_data),
                    color=color,
                    label=severity,
                    alpha=0.7,
                    s=100
                )
        
        ax.set_xlabel('Time')
        ax.set_ylabel('Severity')
        ax.set_title('Threat Detection Timeline')
        ax.legend()
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        return fig
    
    def plot_attacker_profiles(self, attacker_profiles):
        """Visualize attacker profiles"""
        if attacker_profiles.empty:
            print("No attacker profiles to plot")
            return None
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # Skill level distribution
        if 'skill_level' in attacker_profiles.columns:
            skill_counts = attacker_profiles['skill_level'].value_counts()
            axes[0, 0].pie(skill_counts.values, labels=skill_counts.index, autopct='%1.1f%%')
            axes[0, 0].set_title('Attacker Skill Level Distribution')
        
        # Threat level distribution
        if 'threat_level' in attacker_profiles.columns:
            threat_counts = attacker_profiles['threat_level'].value_counts()
            axes[0, 1].bar(threat_counts.index, threat_counts.values, color=['green', 'orange', 'red', 'purple'])
            axes[0, 1].set_title('Threat Level Distribution')
            axes[0, 1].tick_params(axis='x', rotation=45)
        
        # Attack duration distribution
        if 'duration_hours' in attacker_profiles.columns:
            axes[1, 0].hist(attacker_profiles['duration_hours'], bins=10, alpha=0.7, edgecolor='black')
            axes[1, 0].set_title('Attack Duration Distribution (Hours)')
            axes[1, 0].set_xlabel('Duration (hours)')
            axes[1, 0].set_ylabel('Frequency')
        
        # Number of targets
        if 'num_targets' in attacker_profiles.columns:
            target_counts = attacker_profiles['num_targets'].value_counts().sort_index()
            axes[1, 1].bar(target_counts.index, target_counts.values, alpha=0.7, edgecolor='black')
            axes[1, 1].set_title('Number of Targets per Attacker')
            axes[1, 1].set_xlabel('Number of Targets')
            axes[1, 1].set_ylabel('Frequency')
        
        plt.tight_layout()
        return fig
    
    def plot_threat_distribution(self, detection_results):
        """Plot threat type and severity distribution"""
        if detection_results.empty:
            print("No detection results to plot")
            return None
        
        fig, axes = plt.subplots(1, 2, figsize=(15, 6))
        
        # Threat type distribution
        if 'rule_name' in detection_results.columns:
            threat_type_counts = detection_results['rule_name'].value_counts()
            axes[0].bar(threat_type_counts.index, threat_type_counts.values, alpha=0.7, edgecolor='black')
            axes[0].set_title('Threat Type Distribution')
            axes[0].tick_params(axis='x', rotation=45)
            axes[0].set_ylabel('Count')
        
        # Severity distribution
        if 'severity' in detection_results.columns:
            severity_counts = detection_results['severity'].value_counts()
            colors = ['green' if s == 'low' else 'orange' if s == 'medium' else 'red' if s == 'high' else 'purple' 
                     for s in severity_counts.index]
            axes[1].bar(severity_counts.index, severity_counts.values, color=colors, alpha=0.7, edgecolor='black')
            axes[1].set_title('Severity Distribution')
            axes[1].set_ylabel('Count')
        
        plt.tight_layout()
        return fig
    
    def plot_attack_chain(self, attack_chain):
        """Visualize an attack chain as a network graph"""
        if not attack_chain:
            print("No attack chain to visualize")
            return None
        
        G = nx.DiGraph()
        
        # Add nodes and edges based on events
        events = attack_chain.get('events_sequence', [])
        
        for i, event in enumerate(events):
            node_id = f"Event_{i}"
            G.add_node(node_id, 
                      label=f"{event.get('event_type', 'Unknown')}\n{event.get('timestamp', '')}",
                      event_type=event.get('event_type', 'Unknown'))
            
            # Add edges between consecutive events
            if i > 0:
                G.add_edge(f"Event_{i-1}", node_id)
        
        # Create plot
        fig, ax = plt.subplots(figsize=(12, 8))
        pos = nx.spring_layout(G)
        
        # Draw the graph
        nx.draw(G, pos, with_labels=True, node_size=500, node_color='lightblue', 
                font_size=8, font_weight='bold', arrows=True, ax=ax)
        
        ax.set_title(f"Attack Chain: {attack_chain.get('chain_id', 'Unknown')}")
        
        return fig