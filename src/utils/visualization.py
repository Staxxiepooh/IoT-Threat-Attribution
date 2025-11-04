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
        plt.rcParams['patch.edgecolor'] = 'none'  # globally remove patch borders
    
    def plot_detection_timeline(self, detection_results, time_column='timestamp'):
        """Plot detection events timeline with proper time series visualization"""
        if detection_results.empty:
            print("No data to plot")
            return None
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 10))
        
        # Convert to datetime if needed
        detection_results[time_column] = pd.to_datetime(detection_results[time_column])
        
        # Plot 1: Time series of threat counts with severity colors
        time_grouped = detection_results.groupby([
            pd.Grouper(key=time_column, freq='1min'),
            'severity'
        ]).size().unstack(fill_value=0)
        
        # Define colors for each severity
        severity_colors = {'low': 'green', 'medium': 'orange', 'high': 'red', 'critical': 'purple'}
        
        # Plot stacked bar chart
        if not time_grouped.empty:
            time_grouped.plot(kind='bar', stacked=True, ax=ax1, 
                              color=[severity_colors.get(col, 'gray') for col in time_grouped.columns])
            ax1.set_title('Threat Detection Timeline - Threat Counts per Minute')
            ax1.set_xlabel('Time')
            ax1.set_ylabel('Number of Threats')
            ax1.legend(title='Severity')
            ax1.tick_params(axis='x', rotation=45)
        
        # Plot 2: Individual events with severity (no black edge)
        for severity, color in severity_colors.items():
            severity_data = detection_results[detection_results['severity'] == severity]
            if not severity_data.empty:
                ax2.scatter(
                    severity_data[time_column],
                    [severity] * len(severity_data),
                    color=color,
                    label=severity,
                    alpha=0.7,
                    s=100,
                    edgecolors='none',  # removed black border
                    linewidth=0
                )
        
        ax2.set_xlabel('Time')
        ax2.set_ylabel('Severity')
        ax2.set_title('Individual Threat Events Timeline')
        ax2.legend()
        ax2.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        return fig
    
    def plot_threat_frequency(self, detection_results, time_column='timestamp'):
        """Plot threat frequency over time as a line graph"""
        if detection_results.empty:
            print("No data to plot")
            return None
        
        fig, ax = plt.subplots(figsize=(15, 8))
        
        detection_results[time_column] = pd.to_datetime(detection_results[time_column])
        detection_results = detection_results.sort_values(time_column)
        time_series = detection_results.set_index(time_column)
        threat_counts = time_series.resample('30S').size()
        
        ax.plot(threat_counts.index, threat_counts.values, 
                linewidth=2, marker='o', markersize=4, color='red', alpha=0.7)
        ax.fill_between(threat_counts.index, threat_counts.values, alpha=0.3, color='red')
        
        high_threat_periods = threat_counts[threat_counts > threat_counts.mean()]
        if not high_threat_periods.empty:
            ax.scatter(high_threat_periods.index, high_threat_periods.values, 
                       color='darkred', s=100, zorder=5, label='High Threat Peaks', edgecolors='none')
        
        ax.set_xlabel('Time')
        ax.set_ylabel('Number of Threats')
        ax.set_title('Threat Frequency Over Time - 30 Second Intervals')
        ax.grid(True, alpha=0.3)
        ax.legend()
        plt.xticks(rotation=45)
        plt.tight_layout()
        return fig
    
    def plot_severity_timeline(self, detection_results, time_column='timestamp'):
        """Plot severity levels over time with proper spikes"""
        if detection_results.empty:
            print("No data to plot")
            return None
        
        fig, ax = plt.subplots(figsize=(15, 8))
        detection_results[time_column] = pd.to_datetime(detection_results[time_column])
        detection_results = detection_results.sort_values(time_column)
        
        severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        detection_results['severity_numeric'] = detection_results['severity'].map(severity_map)
        
        times = detection_results[time_column]
        severities = detection_results['severity_numeric']
        
        ax.plot(times, severities, 'o-', linewidth=2, markersize=8, alpha=0.7, color='blue')
        
        colors = {1: 'green', 2: 'orange', 3: 'red', 4: 'purple'}
        for severity_num, color in colors.items():
            severity_points = detection_results[detection_results['severity_numeric'] == severity_num]
            if not severity_points.empty:
                ax.scatter(severity_points[time_column], severity_points['severity_numeric'],
                          color=color, s=100, label=f'{list(severity_map.keys())[list(severity_map.values()).index(severity_num)]}',
                          alpha=0.8, edgecolors='none')  # removed black edge
        
        ax.set_yticks(list(severity_map.values()))
        ax.set_yticklabels(list(severity_map.keys()))
        ax.set_ylim(0.5, 4.5)
        ax.set_xlabel('Time')
        ax.set_ylabel('Severity Level')
        ax.set_title('Threat Severity Timeline with Attack Spikes')
        ax.grid(True, alpha=0.3)
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
        
        if 'skill_level' in attacker_profiles.columns:
            skill_counts = attacker_profiles['skill_level'].value_counts()
            axes[0, 0].pie(skill_counts.values, labels=skill_counts.index, autopct='%1.1f%%')
            axes[0, 0].set_title('Attacker Skill Level Distribution')
        
        if 'threat_level' in attacker_profiles.columns:
            threat_counts = attacker_profiles['threat_level'].value_counts()
            colors = ['green' if s == 'low' else 'orange' if s == 'medium' else 'red' if s == 'high' else 'purple' 
                     for s in threat_counts.index]
            axes[0, 1].bar(threat_counts.index, threat_counts.values, color=colors, alpha=0.7)
            axes[0, 1].set_title('Threat Level Distribution')
            axes[0, 1].tick_params(axis='x', rotation=45)
        
        if 'duration_hours' in attacker_profiles.columns:
            axes[1, 0].hist(attacker_profiles['duration_hours'], bins=10, alpha=0.7)
            axes[1, 0].set_title('Attack Duration Distribution (Hours)')
            axes[1, 0].set_xlabel('Duration (hours)')
            axes[1, 0].set_ylabel('Frequency')
        
        if 'num_targets' in attacker_profiles.columns:
            target_counts = attacker_profiles['num_targets'].value_counts().sort_index()
            axes[1, 1].bar(target_counts.index, target_counts.values, alpha=0.7)
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
        
        if 'rule_name' in detection_results.columns:
            threat_type_counts = detection_results['rule_name'].value_counts()
            axes[0].bar(threat_type_counts.index, threat_type_counts.values, alpha=0.7)
            axes[0].set_title('Threat Type Distribution')
            axes[0].tick_params(axis='x', rotation=45)
            axes[0].set_ylabel('Count')
        
        if 'severity' in detection_results.columns:
            severity_counts = detection_results['severity'].value_counts()
            colors = ['green' if s == 'low' else 'orange' if s == 'medium' else 'red' if s == 'high' else 'purple' 
                     for s in severity_counts.index]
            axes[1].bar(severity_counts.index, severity_counts.values, color=colors, alpha=0.7)
            axes[1].set_title('Severity Distribution')
            axes[1].set_ylabel('Count')
        
        plt.tight_layout()
        return fig
    
    def plot_attack_chain(self, attack_chain, device_id=None):
        """Visualize an attack chain as a network graph"""
        if not attack_chain:
            print("No attack chain to visualize")
            return None
        
        G = nx.DiGraph()
        events = attack_chain.get('events_sequence', [])
        
        for i, event in enumerate(events):
            node_id = f"Event_{i+1}"
            timestamp = event.get('timestamp', '')
            event_type = event.get('event_type', 'Unknown')
            source_ip = event.get('source_ip', 'Unknown')
            
            if isinstance(event_type, float):
                event_type = str(event_type)
            event_type = str(event_type)
            
            node_label = f"{event_type}\n{timestamp}\nSrc: {source_ip}"
            G.add_node(node_id, label=node_label, event_type=event_type)
            
            if i > 0:
                prev_node_id = f"Event_{i}"
                G.add_edge(prev_node_id, node_id)
        
        fig, ax = plt.subplots(figsize=(14, 10))
        pos = nx.spring_layout(G, k=3, iterations=50)
        
        node_colors = []
        for node in G.nodes():
            et = G.nodes[node]['event_type'].lower()
            if 'scan' in et:
                node_colors.append('yellow')
            elif 'brute' in et or 'login' in et:
                node_colors.append('red')
            elif 'exploit' in et:
                node_colors.append('purple')
            elif 'access' in et or 'unauthorized' in et:
                node_colors.append('orange')
            elif 'malware' in et or 'virus' in et:
                node_colors.append('darkred')
            elif 'ddos' in et or 'flood' in et:
                node_colors.append('brown')
            else:
                node_colors.append('lightblue')
        
        # Nodes: clean, no outlines
        nx.draw_networkx_nodes(G, pos, node_size=2000, node_color=node_colors, alpha=0.9, edgecolors='none', linewidths=0, ax=ax)
        nx.draw_networkx_edges(G, pos, edge_color='gray', arrows=True, arrowsize=20, arrowstyle='->', width=2, ax=ax)
        nx.draw_networkx_labels(G, pos, {n: G.nodes[n]['label'] for n in G.nodes()}, font_size=8, font_weight='bold', ax=ax)
        
        chain_id = attack_chain.get('chain_id', 'Unknown')
        ax.set_title(f"Attack Chain for Device: {device_id or 'Unknown'}\nChain: {chain_id}", fontsize=14, fontweight='bold', pad=20)
        ax.axis('off')
        
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='yellow', markersize=10, label='Scanning'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=10, label='Brute Force'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='purple', markersize=10, label='Exploitation'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='orange', markersize=10, label='Access'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='darkred', markersize=10, label='Malware'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='brown', markersize=10, label='DDoS'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='lightblue', markersize=10, label='Other')
        ]
        ax.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(1.1, 1))
        
        plt.tight_layout()
        return fig
