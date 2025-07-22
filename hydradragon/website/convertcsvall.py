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
    # Statically set the reference value for all entries.
    reference = "Unknown"
    
    print(f"Processing: {input_file.name} -> {output_file.name} (Reference: '{reference}')")
    
    try:
        # Open the source file, ignoring potential encoding errors in large lists
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                entry = line.strip()
                # Skip empty lines and lines that are comments
                if entry and not entry.startswith('#'):
                    entries.append(entry)
        
        if not entries:
            print(f"  -> No valid entries found in {input_file.name}. Skipping.")
            return

        # Write the collected data to the new CSV file
        with open(output_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            # Write the CSV header
            writer.writerow(['item', 'reference'])
            # Write the data rows
            for entry in entries:
                writer.writerow([entry, reference])
        
        print(f"  -> Successfully converted {len(entries)} entries.")

    except FileNotFoundError:
        print(f"Error: Input file not found at {input_file}")
    except Exception as e:
        print(f"An unexpected error occurred while processing {input_file.name}: {e}")


def batch_process_directory(input_dir: Path, output_dir: Path):
    """
    Scans a directory for .txt files and converts each one to a .csv file
    in the specified output directory.

    Args:
        input_dir: The directory containing the source .txt files.
        output_dir: The directory where the .csv files will be saved.
    """
    # Ensure the output directory exists. If not, create it.
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Input directory:  '{input_dir.resolve()}'")
    print(f"Output directory: '{output_dir.resolve()}'\n")

    found_files = list(input_dir.glob('*.txt'))

    if not found_files:
        print(f"No .txt files found in '{input_dir.resolve()}'.")
        return

    for txt_file in found_files:
        # Create the full path for the output file
        output_filename = txt_file.with_suffix('.csv').name
        output_path = output_dir / output_filename
        
        # Convert the current file
        convert_txt_to_csv(txt_file, output_path)

    print(f"\nBatch processing complete. Processed {len(found_files)} files.")


if __name__ == "__main__":
    # Set up the command-line argument parser
    parser = argparse.ArgumentParser(
        description='Convert all .txt files in a directory to .csv format.\n'
                    'Each CSV will have an "item" column (the entry from the txt)\n'
                    'and a "reference" column (statically set to "Unknown").',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '--input_dir',
        type=str,
        default='.',
        help='Path to the directory with .txt files.\n(Default: the current directory)'
    )
    parser.add_argument(
        '--output_dir',
        type=str,
        default='cleaned',
        help='Path to the directory to save .csv files.\n(Default: a new folder named "cleaned")'
    )

    args = parser.parse_args()

    # Create Path objects from the string arguments
    input_path = Path(args.input_dir)
    output_path = Path(args.output_dir)

    # Start the batch conversion process
    batch_process_directory(input_path, output_path)
