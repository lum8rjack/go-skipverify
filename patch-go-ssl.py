#!/usr/bin/env python3
import subprocess
import argparse

supported_versions_to_bytes = {
        '11': [b"\x00\x0F\x85\xB3\x04\x00\x00", b"\x00\x0F\x84\xB3\x04\x00\x00"],
        '12': [b"\x00\x00\x0F\x85\x43\x05\x00\x00", b"\x00\x00\x0F\x84\x43\x05\x00\x00"],
        '13': [b"\x00\x00\x0F\x85\x32\x05\x00\x00", b"\x00\x00\x0F\x84\x32\x05\x00\x00"],
        '14': [b"\x00\x00\x0F\x85\x48\x05\x00\x00", b"\x00\x00\x0F\x84\x48\x05\x00\x00"],
        '15': [b"\x00\x00\x0F\x85\x3A\x06\x00\x00", b"\x00\x00\x0F\x84\x3A\x06\x00\x00"],
        '16': [b"\x00\x00\x0F\x85\x5A\x06\x00\x00", b"\x00\x00\x0F\x84\x5A\x06\x00\x00"],
        '17': [b"\x00\x00\x0F\x85\x7F\x01\x00\x00", b"\x00\x00\x0F\x84\x7F\x01\x00\x00"],
        '18': [b"\x00\x00\x0F\x85\x7C\x01\x00\x00", b"\x00\x00\x0f\x84\x7C\x01\x00\x00"],
        '19': [b"\x00\x00\x0F\x85\x7B\x01\x00\x00", b"\x00\x00\x0f\x84\x7B\x01\x00\x00"],
        '20': [b"\x00\x00\x0F\x85\x84\x01\x00\x00", b"\x00\x00\x0F\x84\x84\x01\x00\x00"],
        '21': [b"\x00\x00\x0F\x85\x82\x01\x00\x00", b"\x00\x00\x0F\x84\x82\x01\x00\x00"],
        '22': [b"\x00\x00\x0F\x85\x82\x01\x00\x00", b"\x00\x00\x0F\x84\x82\x01\x00\x00"],
        '23': [b"\x00\x00\x0F\x85\x7E\x01\x00\x00", b"\x00\x00\x0F\x84\x7E\x01\x00\x00"],
        '24': [b"\x00\x00\x0F\x85\x7E\x01\x00\x00", b"\x00\x00\x0F\x84\x7E\x01\x00\x00"],
        '25': [b"\x00\x00\x0F\x85\x7E\x01\x00\x00", b"\x00\x00\x0F\x84\x7E\x01\x00\x00"],
        '26': [b"\x00\x00\x0F\x85\x7F\x01\x00\x00", b"\x00\x00\x0F\x84\x7F\x01\x00\x00"],
        '27': [b"\x00\x00\x0F\x85\x81\x01\x00\x00", b"\x00\x00\x0F\x84\x81\x01\x00\x00"]
}


def replace_file_bytes(file_path, old_bytes, new_bytes):
    with open(file_path, 'rb') as f:
        data = f.read()
        position = data.find(old_bytes)
    
    if(-1 == position):
        raise Exception("cannot find bytes, maybe the program is already patched?")

    with open(file_path, 'rb+') as file:
        file.seek(position)
        existing_bytes = file.read(len(old_bytes))
            
        if existing_bytes == old_bytes:
            file.seek(position)
            file.write(new_bytes)
      
def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()
      
def get_go_bin_version(filename):
    output = run_command(f"strings {filename} | grep '^go1' | head -n 1")
    if "" == output:
        output = run_command(f"strings {filename} | grep 'Go cmd/compile'  | head -n 1 | cut -d' ' -f 3")
        if "" == output:
            output = run_command(f"strings {filename} | grep -Eo 'go[0-9]+\\.[0-9]+(\\.[0-9]+)?' | head -n 1")
    return output

def get_args():
    parser = argparse.ArgumentParser(description='Get a filename and patches it ssl verification check')
    parser.add_argument("-f", "--filename", help='File to patch', required=True)
    parser.add_argument("-v", "--version", help='Input version of Golang app')
    parser.add_argument("-g", "--get-version", help='tries to get the app Golang version', action='store_true')
    return parser.parse_args()

def main():
    args = get_args()
    version = get_go_bin_version(args.filename).split('.')[1]
    print(f"Version identified: 1.{version}")

    if args.get_version:
        print("Assuming that the Golang version is: %s" % version)
        return
    if args.version:
        version = args.version

    old_bytes = supported_versions_to_bytes[version][0]
    new_bytes = supported_versions_to_bytes[version][1]
    replace_file_bytes(args.filename, old_bytes, new_bytes)

if "__main__" == __name__:
    main()