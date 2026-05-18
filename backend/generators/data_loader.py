import pandas as pd
import os
from typing import Optional

class DataLoader:
    def __init__(self, csv_path: Optional[str] = None):
        if csv_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            csv_path = os.path.join(base_dir, "dataset", "cybersecurity_threat_detection_logs.csv")
        self.csv_path = csv_path
        self.df: Optional[pd.DataFrame] = None
        self._load()

    def _load(self):
        print(f"Loading dataset from {self.csv_path}...")
        self.df = pd.read_csv(self.csv_path)
        print(f"Loaded {len(self.df)} rows with columns: {list(self.df.columns)}")

    def get_unique_values(self, column: str) -> list:
        if self.df is None:
            return []
        return self.df[column].dropna().unique().tolist()

    def get_sample_row(self) -> dict:
        if self.df is None or self.df.empty:
            return {}
        return self.df.sample(n=1).iloc[0].to_dict()

    def get_dataframe(self) -> pd.DataFrame:
        return self.df

    def get_column_stats(self, column: str) -> dict:
        if self.df is None:
            return {}
        series = self.df[column]
        return {
            "unique_count": int(series.nunique()),
            "top_values": series.value_counts().head(10).to_dict()
        }

data_loader = DataLoader()
