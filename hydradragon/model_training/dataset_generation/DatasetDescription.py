from dataclasses import dataclass
import pathlib

from typing import Tuple, List


@dataclass
class DataRequest:
    name: str
    source_path: pathlib.Path
    num_train: int
    num_test: int
    num_valid: int

    @property
    def total_files(self):
        return self.num_train + self.num_test + self.num_valid

    def __post_init__(self):
        self.source_path = pathlib.Path(self.source_path)
        if not self.source_path.exists():
            raise FileNotFoundError(f"{self.source_path} for DataRequest {self.name} does not exist")

        if self.num_train < 0:
            raise ValueError(f"Training sample count for DataRequest {self.name} must be non-negative")
        if self.num_test < 0:
            raise ValueError(f"Testing sample count for DataRequest {self.name} must be non-negative")
        if self.num_valid < 0:
            raise ValueError(f"Validation sample count for DataRequest {self.name} must be non-negative")


@dataclass
class DatasetDescription:
    name: str
    version: Tuple[int, int]
    save_to_dir: pathlib.Path
    huggingface_user: str
    data_requests: List[DataRequest]

    @property
    def code_dir(self):
        return self.save_to_dir / self.name / "code"

    @property
    def csv_dir(self):
        return self.save_to_dir / self.name / "csv"

    def __post_init__(self):
        self.save_to_dir = pathlib.Path(self.save_to_dir)
        self.version = tuple(self.version)
