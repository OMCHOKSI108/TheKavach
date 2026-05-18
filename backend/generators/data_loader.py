import pandas as pd
import os
import glob
from typing import Optional

class DataLoader:
    def __init__(self, dataset_dir: Optional[str] = None):
        if dataset_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            dataset_dir = os.path.join(base_dir, "dataset")
        self.dataset_dir = dataset_dir
        self.df: Optional[pd.DataFrame] = None
        self._load()

    def _load(self):
        chunk_dir = os.path.join(self.dataset_dir, "chunks")
        if os.path.exists(chunk_dir):
            chunk_files = sorted(glob.glob(os.path.join(chunk_dir, "data_chunk_*.csv")))
            if chunk_files:
                print(f"Loading {len(chunk_files)} dataset chunks...")
                dfs = []
                for f in chunk_files:
                    print(f"  Loading {os.path.basename(f)}...")
                    dfs.append(pd.read_csv(f))
                self.df = pd.concat(dfs, ignore_index=True)
                print(f"Loaded {len(self.df)} total rows from {len(chunk_files)} chunks")
                print(f"Columns: {list(self.df.columns)}")
                return
        csv_path = os.path.join(self.dataset_dir, "cybersecurity_threat_detection_logs.csv")
        if os.path.exists(csv_path):
            print(f"Loading single CSV file: {csv_path}")
            self.df = pd.read_csv(csv_path)
            print(f"Loaded {len(self.df)} rows")
            return
        raise FileNotFoundError(f"No dataset found in {self.dataset_dir}")

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
