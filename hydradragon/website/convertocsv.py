#!/usr/bin/env python3
import csv
import argparse
from pathlib import Path

def convert_txt_to_csv(input_file: Path, output_file: Path):
    """
    Reads a .txt file with one entry per line and converts it to a
    two-column .csv file with a 'reference' column set to "Unknown".

    Args:
        input_file: The path to the source .txt file.
        output_file: The path where the destination .csv file will be saved.
    """
    entries = []
    print(f"Reading from: {input_file}")
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                entry = line.strip()
                # Skip empty lines and comments
                if entry and not entry.startswith('#'):
                    entries.append(entry)
        
        print(f"Found {len(entries)} valid entries.")

        # Write to the CSV file
        with open(output_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            # Write the header
            writer.writerow(['item', 'reference'])
            # Write the data rows
            for entry in entries:
                writer.writerow([entry, "Unknown"])
        
        print(f"Successfully created CSV file: {output_file}")

    except FileNotFoundError:
        print(f"Error: Input file not found at {input_file}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Convert a .txt list to a .csv file with an "Unknown" reference column.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        'input',
        type=str,
        help='Path to the input .txt file.'
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Path for the output .csv file (optional).\n'
             'If not provided, it will be the input filename with a .csv extension.'
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    
    if args.output:
        output_path = Path(args.output)
    else:
        # If no output is specified, create it alongside the input file
        output_path = input_path.with_suffix('.csv')

    # Ensure the output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    convert_txt_to_csv(input_path, output_path)
