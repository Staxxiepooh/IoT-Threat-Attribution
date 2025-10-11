import pandas as pd
import numpy as np
from datetime import datetime
import os

class LogParser:
    def __init__(self):
        self.supported_formats = ['.csv', '.json']
    
    def parse_logs(self, file_path):
        """
        Parse IoT logs from various file formats
        """
        try:
            if file_path.endswith('.csv'):
                return self._parse_csv(file_path)
            elif file_path.endswith('.json'):
                return self._parse_json(file_path)
            else:
                raise ValueError(f"Unsupported file format. Supported formats: {self.supported_formats}")
        except Exception as e:
            print(f"Error parsing logs: {e}")
            return None
    
    def _parse_csv(self, file_path):
        """Parse CSV log files"""
        df = pd.read_csv(file_path)
        
        # Convert timestamp to datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Add additional parsed features
        df = self._extract_features(df)
        
        return df
    
    def _parse_json(self, file_path):
        """Parse JSON log files"""
        df = pd.read_json(file_path)
        
        # Convert timestamp to datetime if exists
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Add additional parsed features
        df = self._extract_features(df)
        
        return df
    
    def _extract_features(self, df):
        """Extract additional features from log data"""
        # Add hour of day
        if 'timestamp' in df.columns:
            df['hour'] = df['timestamp'].dt.hour
        
        # Add payload size category
        if 'payload_size' in df.columns:
            df['payload_category'] = pd.cut(
                df['payload_size'], 
                bins=[0, 512, 1024, 2048, float('inf')],
                labels=['small', 'medium', 'large', 'very_large']
            )
        
        # Add IP type (internal/external)
        if 'source_ip' in df.columns:
            df['source_ip_type'] = df['source_ip'].apply(self._classify_ip)
        
        return df
    
    def _classify_ip(self, ip):
        """Classify IP as internal or external"""
        if ip.startswith(('192.168.', '10.', '172.')):
            return 'internal'
        else:
            return 'external'
    
    def validate_logs(self, df):
        """Validate the parsed log data"""
        required_columns = ['timestamp', 'device_id', 'event_type']
        
        for col in required_columns:
            if col not in df.columns:
                raise ValueError(f"Missing required column: {col}")
        
        # Check for null values in critical columns
        critical_cols = ['timestamp', 'device_id', 'event_type']
        for col in critical_cols:
            if df[col].isnull().any():
                print(f"Warning: Null values found in {col}")
        
        return True

# Example usage
if __name__ == "__main__":
    parser = LogParser()
    sample_data = parser.parse_logs('../../../data/raw/sample_iot_logs.csv')
    if sample_data is not None:
        print("Sample data parsed successfully:")
        print(sample_data.head())