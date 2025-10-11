import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.cluster import DBSCAN
import warnings
warnings.filterwarnings('ignore')

class AnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
    
    def preprocess_data(self, df):
        """Preprocess data for anomaly detection"""
        df_processed = df.copy()
        
        # Encode categorical variables
        categorical_columns = ['event_type', 'protocol', 'action', 'threat_level']
        
        for col in categorical_columns:
            if col in df_processed.columns:
                self.label_encoders[col] = LabelEncoder()
                df_processed[col] = self.label_encoders[col].fit_transform(
                    df_processed[col].astype(str)
                )
        
        # Select numerical features for anomaly detection
        feature_columns = [
            'payload_size', 'event_type', 'protocol', 'action', 'threat_level'
        ]
        
        # Filter available columns
        available_features = [col for col in feature_columns if col in df_processed.columns]
        
        if not available_features:
            raise ValueError("No suitable features found for anomaly detection")
        
        features = df_processed[available_features].fillna(0)
        
        return features
    
    def detect_anomalies_isolation_forest(self, df):
        """Detect anomalies using Isolation Forest"""
        try:
            features = self.preprocess_data(df)
            
            # Scale features
            scaled_features = self.scaler.fit_transform(features)
            
            # Fit Isolation Forest
            anomalies = self.isolation_forest.fit_predict(scaled_features)
            
            # Convert predictions (-1 for anomalies, 1 for normal)
            df['anomaly_score'] = self.isolation_forest.decision_function(scaled_features)
            df['is_anomaly'] = anomalies == -1
            
            return df
        
        except Exception as e:
            print(f"Error in anomaly detection: {e}")
            return df
    
    def detect_behavioral_anomalies(self, df):
        """Detect behavioral anomalies based on device patterns"""
        anomalies = []
        
        # Group by device and analyze behavior
        for device_id in df['device_id'].unique():
            device_data = df[df['device_id'] == device_id]
            
            # Check for unusual event frequency
            if len(device_data) > 0:
                event_frequency = len(device_data)
                avg_payload = device_data['payload_size'].mean() if 'payload_size' in device_data.columns else 0
                
                # Simple heuristic: if device has very high event frequency or large payloads
                if event_frequency > 10 or avg_payload > 2000:
                    for _, event in device_data.iterrows():
                        anomalies.append({
                            'device_id': device_id,
                            'timestamp': event['timestamp'],
                            'anomaly_type': 'behavioral',
                            'severity': 'medium',
                            'evidence': f'Unusual behavior pattern: {event_frequency} events, avg payload: {avg_payload:.2f}',
                            'source_ip': event.get('source_ip', 'unknown')
                        })
        
        return pd.DataFrame(anomalies)
    
    def cluster_analysis(self, df, eps=0.5, min_samples=2):
        """Perform cluster analysis using DBSCAN"""
        try:
            features = self.preprocess_data(df)
            scaled_features = self.scaler.fit_transform(features)
            
            # Apply DBSCAN
            clustering = DBSCAN(eps=eps, min_samples=min_samples).fit(scaled_features)
            
            df['cluster'] = clustering.labels_
            
            # Anomalies are points labeled as -1 (noise)
            dbscan_anomalies = df[df['cluster'] == -1].copy()
            
            return dbscan_anomalies
        
        except Exception as e:
            print(f"Error in cluster analysis: {e}")
            return pd.DataFrame()

# Example usage
if __name__ == "__main__":
    from data_collection.log_parser import LogParser
    
    parser = LogParser()
    df = parser.parse_logs('../../../data/raw/sample_iot_logs.csv')
    
    detector = AnomalyDetector()
    
    # Isolation Forest anomalies
    anomaly_df = detector.detect_anomalies_isolation_forest(df)
    print("Anomalies detected:", anomaly_df['is_anomaly'].sum())
    
    # Behavioral anomalies
    behavioral_anomalies = detector.detect_behavioral_anomalies(df)
    print("Behavioral anomalies:", len(behavioral_anomalies))
    
    # Cluster analysis
    cluster_anomalies = detector.cluster_analysis(df)
    print("Cluster anomalies:", len(cluster_anomalies))