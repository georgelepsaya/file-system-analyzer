import argparse
from file_system_analyzer.models.file_system_analyzer import FileSystemAnalyzer
from pprint import pprint
import os
from colorama import Fore, Back, Style, init

init()

def parse_output(output, large_files):
    for file_type, files in output.items():
        print(Fore.BLUE + Style.BRIGHT + f"Category: {file_type.capitalize()}")
        print(Fore.CYAN + f"Size: {files['size']}")
        print(Style.RESET_ALL, end="")
        for file in files["files"]:
            print((Fore.RED if file['path'] in large_files else "") + file['path'])
        print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", help="directory to be analyzed")
    parser.add_argument("-t", "--threshold", help="size threshold to identify large files", type=int)
    args = parser.parse_args()
    
    fsa = FileSystemAnalyzer(args.directory, args.threshold)
    fsa.categorize_files()
    # pprint(fsa.files_by_category)
    parse_output(fsa.files_by_category, fsa.large_files)
    # pprint(fsa.large_files)
    # pprint(fsa.unusual_permissions_files)
