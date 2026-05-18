import pandas as pd
import os
import glob
import random
from typing import Optional, List

class DataLoader:
    def __init__(self, dataset_dir: Optional[str] = None, max_chunks_in_memory: int = 2):
        if dataset_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            dataset_dir = os.path.join(base_dir, "dataset")
        self.dataset_dir = dataset_dir
        self.max_chunks = max_chunks_in_memory
        self.chunk_files: List[str] = []
        self.loaded_dfs: List[pd.DataFrame] = []
        self.loaded_indices: List[int] = []
        self._rows_per_chunk = 0
        self._discover_chunks()

    def _discover_chunks(self):
        chunk_dir = os.path.join(self.dataset_dir, "chunks")
        if os.path.exists(chunk_dir):
            self.chunk_files = sorted(glob.glob(os.path.join(chunk_dir, "data_chunk_*.csv")))
        if not self.chunk_files:
            csv_path = os.path.join(self.dataset_dir, "cybersecurity_threat_detection_logs.csv")
            if os.path.exists(csv_path):
                self.chunk_files = [csv_path]
        if not self.chunk_files:
            raise FileNotFoundError(f"No dataset found in {self.dataset_dir}")
        self._load_initial_chunks()

    def _load_initial_chunks(self):
        to_load = min(self.max_chunks, len(self.chunk_files))
        for i in range(to_load):
            self._load_chunk(i)

    def _load_chunk(self, index: int):
        if index in self.loaded_indices:
            return
        while len(self.loaded_indices) >= self.max_chunks:
            self.loaded_indices.pop(0)
            self.loaded_dfs.pop(0)
        print(f"  Loading chunk {index}: {os.path.basename(self.chunk_files[index])}...")
        df = pd.read_csv(self.chunk_files[index])
        self.loaded_indices.append(index)
        self.loaded_dfs.append(df)
        if self._rows_per_chunk == 0:
            self._rows_per_chunk = len(df)

    def _ensure_chunk_loaded(self, index: int):
        if index not in self.loaded_indices:
            self._load_chunk(index)

    def get_sample_row(self) -> dict:
        chunk_idx = random.randint(0, len(self.chunk_files) - 1)
        self._ensure_chunk_loaded(chunk_idx)
        pos = self.loaded_indices.index(chunk_idx)
        return self.loaded_dfs[pos].sample(n=1).iloc[0].to_dict()

    def get_sample_rows(self, n: int = 50) -> List[dict]:
        rows = []
        chunk_indices = random.sample(range(len(self.chunk_files)), min(3, len(self.chunk_files)))
        per_chunk = max(1, n // len(chunk_indices))
        for ci in chunk_indices:
            self._ensure_chunk_loaded(ci)
            pos = self.loaded_indices.index(ci)
            sample = self.loaded_dfs[pos].sample(n=min(per_chunk, len(self.loaded_dfs[pos])))
            rows.extend(sample.to_dict('records'))
        random.shuffle(rows)
        return rows[:n]

    def get_unique_values(self, column: str) -> list:
        values = set()
        for i in range(len(self.chunk_files)):
            self._ensure_chunk_loaded(i)
            pos = self.loaded_indices.index(i)
            values.update(self.loaded_dfs[pos][column].dropna().unique().tolist())
        return list(values)

    def get_dataframe(self) -> Optional[pd.DataFrame]:
        if self.loaded_dfs:
            return self.loaded_dfs[0]
        return None

    def get_column_stats(self, column: str) -> dict:
        all_values = []
        for i in range(len(self.chunk_files)):
            self._ensure_chunk_loaded(i)
            pos = self.loaded_indices.index(i)
            all_values.extend(self.loaded_dfs[pos][column].dropna().tolist())
        series = pd.Series(all_values)
        return {
            "unique_count": int(series.nunique()),
            "top_values": series.value_counts().head(10).to_dict()
        }

    def get_total_rows(self) -> int:
        return self._rows_per_chunk * len(self.chunk_files)

    def get_columns(self) -> List[str]:
        if self.loaded_dfs:
            return list(self.loaded_dfs[0].columns)
        return []

data_loader = DataLoader()
