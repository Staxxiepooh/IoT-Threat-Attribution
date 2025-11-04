#!/usr/bin/env python3
"""
Context Chain Builder for IoT Threat Attribution

Provides:
- ContextChainBuilder.build_attack_chains(parsed_logs, detections): builds multi-hop chains
  by following destination IP hops and mapping IP -> device_id.
- ContextChainBuilder.visualize_chain_improved(chain, save_path=None): visualizes a chain as a
  compact left-to-right chronological directed graph with readable labels and severity color coding.
"""

from typing import List, Dict, Any, Optional
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches


class ContextChainBuilder:
    def __init__(self):
        # severity ranking for aggregation
        self.severity_levels = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }

    def build_attack_chains(self, parsed_logs: pd.DataFrame, detections: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Build multi-hop attack chains by following destination IP hops and mapping IP -> device_id.
        Returns a list of chain dicts compatible with visualize_chain_improved().
        """
        if parsed_logs is None or parsed_logs.empty:
            return []

        parsed = parsed_logs.copy()
        parsed['timestamp'] = pd.to_datetime(parsed['timestamp'], errors='coerce')

        det = detections.copy() if detections is not None else pd.DataFrame()
        if not det.empty and 'timestamp' in det.columns:
            det['timestamp'] = pd.to_datetime(det['timestamp'], errors='coerce')

        # Merge detections with parsed logs
        if not det.empty:
            merged = pd.merge(
                parsed, det,
                on=['source_ip', 'device_id', 'timestamp'],
                how='left', suffixes=('', '_det')
            )
        else:
            merged = parsed

        # Build IP → device_id mapping
        ip_to_device = {}
        if 'device_id' in parsed.columns:
            src_map = parsed.dropna(subset=['device_id', 'source_ip']).sort_values('timestamp') \
                             .drop_duplicates(subset=['source_ip'], keep='last') \
                             .set_index('source_ip')['device_id'].to_dict()
            ip_to_device.update(src_map)
            if 'destination_ip' in parsed.columns:
                dst_map = parsed.dropna(subset=['device_id', 'destination_ip']).sort_values('timestamp') \
                                 .drop_duplicates(subset=['destination_ip'], keep='last') \
                                 .set_index('destination_ip')['device_id'].to_dict()
                ip_to_device.update(dst_map)

        chains: List[Dict[str, Any]] = []
        starting_sources = merged['source_ip'].dropna().unique().tolist()

        for src in starting_sources:
            chain_events: List[Dict[str, Any]] = []
            visited_srcs = set()
            queue = [src]

            while queue:
                cur_src = queue.pop(0)
                if cur_src in visited_srcs:
                    continue
                visited_srcs.add(cur_src)

                cur_events = merged[merged['source_ip'] == cur_src].sort_values('timestamp').to_dict('records')
                if cur_events:
                    chain_events.extend(cur_events)

                for ev in cur_events:
                    dst_ip = ev.get('destination_ip')
                    if not dst_ip:
                        continue
                    mapped_device = ip_to_device.get(dst_ip)
                    if mapped_device:
                        possible_srcs = parsed[parsed['device_id'] == mapped_device]['source_ip'].dropna().unique().tolist()
                        for possible_src in possible_srcs:
                            if possible_src not in visited_srcs and possible_src not in queue:
                                queue.append(possible_src)

            # Deduplicate
            seen = set()
            deduped_events = []
            for ev in sorted(chain_events, key=lambda x: x.get('timestamp') or pd.Timestamp(0)):
                key = (
                    str(ev.get('timestamp')),
                    str(ev.get('source_ip')),
                    str(ev.get('destination_ip')),
                    str(ev.get('device_id')),
                    str(ev.get('event_type', ev.get('rule_name', '')))
                )
                if key not in seen:
                    seen.add(key)
                    cleaned = {k: (None if pd.isna(v) else v) for k, v in ev.items()}
                    deduped_events.append(cleaned)

            if not deduped_events:
                continue

            start = pd.to_datetime(deduped_events[0].get('timestamp'), errors='coerce')
            end = pd.to_datetime(deduped_events[-1].get('timestamp'), errors='coerce')
            duration_minutes = ((end - start).total_seconds() / 60) if (pd.notna(start) and pd.notna(end)) else 0.0

            attack_types = list({e.get('rule_name') or e.get('event_type') for e in deduped_events if e.get('rule_name') or e.get('event_type')})
            severities = [(e.get('severity') or e.get('threat_level') or '').lower() for e in deduped_events]
            max_sev = max(severities, key=lambda s: self.severity_levels.get(s, 0)) if severities else None

            chain = {
                "chain_id": f"chain_{src}_{start.strftime('%Y%m%d_%H%M%S') if pd.notna(start) else 'unknown'}",
                "source_ip": src,
                "device_id": deduped_events[0].get('device_id'),
                "start_time": start.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(start) else None,
                "end_time": end.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(end) else None,
                "duration_minutes": round(duration_minutes, 2),
                "attack_types": attack_types,
                "max_severity": max_sev,
                "event_count": len(deduped_events),
                "events_sequence": deduped_events,
                "confidence_score": round(min(1.0, len(deduped_events) * 0.15), 2)
            }
            chains.append(chain)

        return chains

    def visualize_chain_improved(self, chains: List[Dict[str, Any]], save_path: Optional[str] = None):
        """
        Per-device circular attack chain visualization.
        Evenly spaced nodes (like clock positions) with directional arrows.
        Each device's chain is shown separately with event-type color coding.
        """
        import matplotlib.pyplot as plt
        import networkx as nx
        import numpy as np
        import os

        if not chains:
            print("[!] No attack chains to visualize.")
            return

        # Group by device
        device_groups = {}
        for chain in chains:
            device_id = chain.get("device_id", "unknown_device")
            device_groups.setdefault(device_id, []).append(chain)

        # Color map by event type
        event_colors = {
            "scan": "yellow",
            "bruteforce": "red",
            "login": "red",
            "exploit": "purple",
            "access": "orange",
            "unauthorized": "orange",
            "malware": "darkred",
            "virus": "darkred",
            "ddos": "brown",
            "flood": "brown",
            "other": "lightblue"
        }

        for device_id, device_chains in device_groups.items():
            for chain in device_chains:
                events = chain.get("events_sequence", [])
                if not events:
                    continue

                # Create directed graph
                G = nx.DiGraph()

                # Add nodes and edges
                for i, event in enumerate(events):
                    event_type = str(event.get("event_type", "unknown")).lower()
                    timestamp = str(event.get("timestamp", ""))
                    src_ip = str(event.get("source_ip", ""))
                    label = f"{event_type}\n{timestamp}\nSrc: {src_ip}"

                    node_id = f"event_{i}"
                    G.add_node(node_id, label=label, event_type=event_type)

                    if i > 0:
                        G.add_edge(f"event_{i-1}", node_id)

                # Assign colors
                node_colors = []
                for node in G.nodes():
                    et = G.nodes[node]["event_type"]
                    color = "lightblue"
                    for key, val in event_colors.items():
                        if key in et:
                            color = val
                            break
                    node_colors.append(color)

                # === Evenly spaced circular layout ===
                num_nodes = len(G.nodes)
                angle_step = 2 * np.pi / num_nodes
                radius = 1.0
                pos = {
                    node: (radius * np.cos(i * angle_step), radius * np.sin(i * angle_step))
                    for i, node in enumerate(G.nodes())
                }

                # Plot setup
                plt.figure(figsize=(12, 8))

                # Draw arrows for direction clarity
                nx.draw_networkx_edges(
                    G, pos,
                    arrows=True,
                    arrowstyle="->",
                    arrowsize=16,
                    edge_color="gray",
                    width=1.5,
                    connectionstyle="arc3,rad=0.1"
                )

                # Draw nodes
                nx.draw_networkx_nodes(
                    G, pos,
                    node_color=node_colors,
                    node_size=2000,
                    alpha=0.9,
                    edgecolors="none"
                )

                # Draw labels
                nx.draw_networkx_labels(
                    G, pos,
                    labels={n: G.nodes[n]["label"] for n in G.nodes()},
                    font_size=8,
                    font_weight="bold"
                )

                # Add title
                plt.title(
                    f"Attack Chain for Device: {device_id}\nChain: {chain.get('chain_id')}",
                    fontsize=12,
                    fontweight="bold",
                    pad=20
                )

                # Legend (same as reference)
                legend_elements = [
                    plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="yellow", label="Scanning", markersize=10),
                    plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="red", label="Brute Force", markersize=10),
                    plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="purple", label="Exploitation", markersize=10),
                    plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="orange", label="Access", markersize=10),
                    plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="darkred", label="Malware", markersize=10),
                    plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="brown", label="DDoS", markersize=10),
                    plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="lightblue", label="Other", markersize=10)
                ]
                plt.legend(handles=legend_elements, loc="upper right", bbox_to_anchor=(1.1, 1))

                # Clean up layout
                plt.axis("off")
                plt.tight_layout()

                # Save or show
                if save_path:
                    os.makedirs(save_path, exist_ok=True)
                    filename = os.path.join(save_path, f"{device_id}_{chain.get('chain_id')}.png")
                    plt.savefig(filename, dpi=300, bbox_inches="tight")
                    plt.close()
                else:
                    plt.show()
