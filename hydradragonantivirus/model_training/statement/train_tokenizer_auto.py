import logging
import pathlib
import click

from datasets import ReadInstruction, load_dataset
from huggingface_hub import HfApi, repo_exists
from StatementConfiguration import StatementConfiguration, parse_statement_config_json
from tokenizers import Tokenizer
from transformers import AutoTokenizer


def get_untrained_tokenizer(tokenizer_repo_name: str) -> AutoTokenizer:
    tokenizer_dir = pathlib.Path(__file__).parent / tokenizer_repo_name
    tokenizer = AutoTokenizer.from_pretrained(tokenizer_dir)
    return tokenizer


def save_and_upload_tokenizer(
    tokenizer: Tokenizer,
    tokenizer_json_path: pathlib.Path,
    tokenizer_repo_name: str,
    dataset_name: str,
):
    # Save the tokenizer locally
    tokenizer.save_pretrained(str(tokenizer_json_path.parent.resolve()))

    # Upload files to Hugging Face Hub
    api = HfApi()
    api.create_repo(tokenizer_repo_name, exist_ok=True, private=True)
    api.upload_file(
        path_in_repo="tokenizer_config.json",
        path_or_fileobj=str(tokenizer_json_path.parent / "tokenizer_config.json"),
        repo_id=tokenizer_repo_name,
        commit_message=f"Trained tokenizer using {dataset_name}",
    )
    api.upload_file(
        path_in_repo="vocab.json",
        path_or_fileobj=str(tokenizer_json_path.parent / "vocab.json"),
        repo_id=tokenizer_repo_name,
        commit_message="Extracted vocabulary from tokenizer",
    )
    api.upload_file(
        path_in_repo="merges.txt",
        path_or_fileobj=str(tokenizer_json_path.parent / "merges.txt"),
        repo_id=tokenizer_repo_name,
        commit_message="Extracted merges from tokenizer",
    )
    api.upload_file(
        path_in_repo="tokenizer.json",
        path_or_fileobj=str(tokenizer_json_path.parent / "tokenizer.json"),
        repo_id=tokenizer_repo_name,
        commit_message="Extracted tokenizer",
    )
    api.upload_file(
        path_in_repo="special_tokens_map.json",
        path_or_fileobj=str(tokenizer_json_path.parent / "special_tokens_map.json"),
        repo_id=tokenizer_repo_name,
        commit_message="Extracted special tokens map",
    )


def train_tokenizer(config: StatementConfiguration, tokenizer_json_path: pathlib.Path):
    if repo_exists(config.base_repo_name):
        logging.error(f"{config.base_repo_name} has already exists")
        exit(1)

    tokenizer = get_untrained_tokenizer("tokenizer")

    train_dataset = load_dataset(
        config.dataset_repo_name,
        token=True,
        split=ReadInstruction("train", to=config.dataset_percentage, unit="%"),
    )["bytecode"]

    tokenizer = tokenizer.train_new_from_iterator(train_dataset, vocab_size=30000)
    save_and_upload_tokenizer(
        tokenizer,
        tokenizer_json_path,
        config.tokenizer_repo_name,
        config.dataset_repo_name,
    )


@click.command(help="Training script for the bytecode tokenizer for the statement model given a statement json.")
@click.argument("json_path", type=str)
def main(json_path: str):
    json_file_path = pathlib.Path(json_path)
    statement_config = parse_statement_config_json(json_file_path)
    train_tokenizer(statement_config, json_file_path)


if __name__ == "__main__":
    main()
