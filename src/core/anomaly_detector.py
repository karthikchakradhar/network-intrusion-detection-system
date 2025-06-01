from sklearn.ensemble import IsolationForest
import pandas as pd

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.01)
        
    def train(self, normal_traffic_csv):
        df = pd.read_csv(normal_traffic_csv)
        self.model.fit(df[['packet_size', 'protocol', 'frequency']])
    
    def detect(self, packet_features):
        return self.model.predict([packet_features])[0] == -1