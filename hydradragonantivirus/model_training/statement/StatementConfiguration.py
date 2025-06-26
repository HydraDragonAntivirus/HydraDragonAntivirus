from dataclasses import dataclass

import pathlib
import json
import logging


@dataclass
class TrainingParameters:
    batch_size: int
    epochs: int
    learning_rate: float


@dataclass
class StatementConfiguration:
    base_repo_name: str
    dataset_repo_name: str
    tokenizer_repo_name: str
    pretrained_seq2seq_repo_name: str
    cache_dir: pathlib.Path
    max_token_length: int
    dataset_percentage: int
    do_eval: bool
    fp16: bool
    statement_training_parameters: TrainingParameters

    @property
    def tokenized_dataset_repo_name(self):
        return self.dataset_repo_name + "-tokenized"

    @property
    def statement_model_repo_name(self):
        return self.base_repo_name + "-statement"

    @property
    def statement_model_dir(self):
        return self.cache_dir / "models" / self.statement_model_repo_name

    @property
    def log_dir(self):
        return self.statement_model_dir / "logs"

    def __post_init__(self):
        self.cache_dir = pathlib.Path(self.cache_dir)


def parse_statement_config_json(json_file_path: pathlib.Path, logger: logging.Logger = None) -> StatementConfiguration:
    if not json_file_path.exists():
        raise FileNotFoundError(f"{json_file_path} does not exist")

    if logger:
        logger.info(f"Loading model description from {json_file_path}...")

    with json_file_path.open() as json_file:
        statement_config_dict = json.load(json_file)

    statement_config_dict["statement_training_parameters"] = TrainingParameters(**statement_config_dict["statement_training_parameters"])
    return StatementConfiguration(**statement_config_dict)
