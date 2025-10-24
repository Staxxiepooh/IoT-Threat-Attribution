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
        """Plot detection events timeline with proper time series visualization"""
        if detection_results.empty:
            print("No data to plot")
            return None
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 10))
        
        # Convert to datetime if needed
        detection_results[time_column] = pd.to_datetime(detection_results[time_column])
        
        # Plot 1: Time series of threat counts with severity colors
        time_grouped = detection_results.groupby([
            pd.Grouper(key=time_column, freq='1min'),  # Group by 1-minute intervals
            'severity'
        ]).size().unstack(fill_value=0)
        
        # Define colors for each severity
        severity_colors = {'low': 'green', 'medium': 'orange', 'high': 'red', 'critical': 'purple'}
        
        # Plot stacked bar chart for threat counts over time
        if not time_grouped.empty:
            time_grouped.plot(kind='bar', stacked=True, ax=ax1, color=[severity_colors.get(col, 'gray') for col in time_grouped.columns])
            ax1.set_title('Threat Detection Timeline - Threat Counts per Minute')
            ax1.set_xlabel('Time')
            ax1.set_ylabel('Number of Threats')
            ax1.legend(title='Severity')
            ax1.tick_params(axis='x', rotation=45)
        
        # Plot 2: Individual events with severity
        for severity, color in severity_colors.items():
            severity_data = detection_results[detection_results['severity'] == severity]
            if not severity_data.empty:
                # Convert timestamps to numeric for plotting
                times_numeric = pd.to_numeric(severity_data[time_column]) / 10**9  # Convert to seconds
                
                ax2.scatter(
                    severity_data[time_column],
                    [severity] * len(severity_data),
                    color=color,
                    label=severity,
                    alpha=0.7,
                    s=100,
                    edgecolors='black',
                    linewidth=0.5
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
        
        # Convert to datetime and sort
        detection_results[time_column] = pd.to_datetime(detection_results[time_column])
        detection_results = detection_results.sort_values(time_column)
        
        # Resample to 30-second intervals and count threats
        time_series = detection_results.set_index(time_column)
        threat_counts = time_series.resample('30S').size()
        
        # Plot the line graph
        ax.plot(threat_counts.index, threat_counts.values, 
                linewidth=2, marker='o', markersize=4, color='red', alpha=0.7)
        
        # Fill under the line
        ax.fill_between(threat_counts.index, threat_counts.values, alpha=0.3, color='red')
        
        # Add markers for high threat periods
        high_threat_periods = threat_counts[threat_counts > threat_counts.mean()]
        if not high_threat_periods.empty:
            ax.scatter(high_threat_periods.index, high_threat_periods.values, 
                      color='darkred', s=100, zorder=5, label='High Threat Peaks')
        
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
        
        # Convert to datetime and sort
        detection_results[time_column] = pd.to_datetime(detection_results[time_column])
        detection_results = detection_results.sort_values(time_column)
        
        # Map severity to numerical values for plotting
        severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        detection_results['severity_numeric'] = detection_results['severity'].map(severity_map)
        
        # Create timeline with severity levels
        times = detection_results[time_column]
        severities = detection_results['severity_numeric']
        
        # Plot severity levels over time
        ax.plot(times, severities, 'o-', linewidth=2, markersize=8, alpha=0.7, color='blue')
        
        # Add colored regions for different severity levels
        colors = {1: 'green', 2: 'orange', 3: 'red', 4: 'purple'}
        for severity_num, color in colors.items():
            severity_points = detection_results[detection_results['severity_numeric'] == severity_num]
            if not severity_points.empty:
                ax.scatter(severity_points[time_column], severity_points['severity_numeric'], 
                          color=color, s=100, label=f'{list(severity_map.keys())[list(severity_map.values()).index(severity_num)]}', 
                          alpha=0.8, edgecolors='black')
        
        # Customize y-axis
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
        
        # Skill level distribution
        if 'skill_level' in attacker_profiles.columns:
            skill_counts = attacker_profiles['skill_level'].value_counts()
            axes[0, 0].pie(skill_counts.values, labels=skill_counts.index, autopct='%1.1f%%')
            axes[0, 0].set_title('Attacker Skill Level Distribution')
        
        # Threat level distribution
        if 'threat_level' in attacker_profiles.columns:
            threat_counts = attacker_profiles['threat_level'].value_counts()
            colors = ['green' if s == 'low' else 'orange' if s == 'medium' else 'red' if s == 'high' else 'purple' 
                     for s in threat_counts.index]
            axes[0, 1].bar(threat_counts.index, threat_counts.values, color=colors, alpha=0.7, edgecolor='black')
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