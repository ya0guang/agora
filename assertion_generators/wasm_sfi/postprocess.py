#!/usr/bin/python3

import argparse
from typing import List


def remove_redundant_lines(lines: List[str]) -> List[str]:
    # Use a set to keep track of seen lines
    seen_lines = set()

    # Use a list to store the unique lines in their original order
    unique_lines = []

    for line in lines:
        # If the line has not been seen before, add it to the unique_lines list
        if line not in seen_lines:
            unique_lines.append(line)
            seen_lines.add(line)

    return unique_lines


def main():
    # Set up command-line argument parser
    parser = argparse.ArgumentParser(
        description='Remove redundant lines from a file.')
    parser.add_argument('input_file', type=str, help='Path to the input file.')
    parser.add_argument('output_file',
                        type=str,
                        help='Path to the output file.')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Read lines from the input file
    with open(args.input_file, 'r') as input_file:
        lines = input_file.readlines()

    # Remove redundant lines
    unique_lines = remove_redundant_lines(lines)

    # Write the unique lines to the output file
    with open(args.output_file, 'w') as output_file:
        output_file.writelines(unique_lines)


if __name__ == '__main__':
    main()
