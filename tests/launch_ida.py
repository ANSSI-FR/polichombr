"""
    This file is part of Polichombr
        (c) ANSSI-FR 2018

    Description:
        Utility script to launch two IDA on the same binary
        Useful for testing
"""

import argparse
from shutil import copyfile
import subprocess
import multiprocessing


def launch_ida_with_script(ida_path, script, binary):
    if ida_path is None:
        ida_path = "ida"
    else:
        ida_path += "/ida"
    args = [ida_path, "-c", "-S" + script, binary]
    process = subprocess.Popen(args)
    return process

def prepare_second_sample(binary):
    new_name = binary + ".copy"
    copyfile(binary, new_name)
    return new_name

def main(args):
    if args.prepare_script:
        p = launch_ida_with_script(args.ida_path, args.prepare_script, args.binary)
        p.communicate()

    launch_ida_with_script(args.ida_path, args.script, args.binary)
    new_sample = prepare_second_sample(args.binary)

    p = launch_ida_with_script(args.ida_path, args.script, new_sample)
    p.communicate()

def get_args():
    parser = argparse.ArgumentParser(description="Skelenox testing")
    parser.add_argument("--binary",
                        help="the binary on which to launch ida",
                        default="tests/example_pe.bin")
    parser.add_argument("--ida-path", help="Path to IDA")
    parser.add_argument("--script",
                        help="An alternative script to run",
                        default="skelenox.py")

    parser.add_argument("--prepare-script", help="A script to prepare the database")

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    main(get_args())
