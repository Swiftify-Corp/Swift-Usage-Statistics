#!/usr/bin/env python3

from pathlib import Path
import plistlib
import subprocess
import re
import csv
import os

def get_swift_version(txt):
    swift_version_search = re.search("Swift = (.+)", txt)
    swift_version = "not swift"
    if swift_version_search:
        swift_version = swift_version_search.group(1)
    print(swift_version)
    return swift_version

def is_executable(file_path):
    file_info = subprocess.run(["file", file_path], capture_output=True)
    return 'Mach-O' in str(file_info.stdout)

def find_executable_in(path):
    executables = [file for file in path.iterdir()
                   if is_executable(file)]
    return None if len(executables) == 0 else executables[0]

def get_text_of_executable(executable_path):
    text = subprocess.run(["ipsw", "macho", "info", executable_path, "--objc"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode('utf-8')
    return text

def class_dump(text):
    protocols = re.findall("@protocol (.+)", text)
    classes = re.findall("0x.{11} ([^[]\w+) :", text)
    both = classes + protocols
    return both

def is_apple_class(class_tuple):
    prefixes = ["NS", "UI", "CA", "SCN", "SK", "CI", "AB", "ML", "GK", "AV", "MK", "SF", "WK", "AS", "CL"]
    for prefix in prefixes:
        pattern = re.compile(f'{prefix}[A-Z][a-z]+')
        if pattern.match(class_tuple):
            return True
    return False

def percentage_classes_in_swift(classes, app_name):
    classes = [item for item in classes if not is_apple_class(item)]
    fw = open
    str_classes = "\n".join(classes)
    save_to_file(str_classes, "all_classes.txt", app_name)
    if len(classes) == 0: return 0.0
    swift_classes = [item for item in classes if item.startswith("_T")]
    str_swift_classes = "\n".join(swift_classes)
    save_to_file(str_swift_classes, "swift_classes.txt", app_name)
    return float(len(swift_classes)) / float(len(classes))

def save_to_file(content, file_name, app_name):
    directory_path = f"./classes/{app_name}/"
    os.makedirs(directory_path, exist_ok=True)
    path = f"{directory_path}{file_name}"
    f = open(path, "w")
    f.write(content)
    f.close()
    
def analyze_app(path):
    results = {}
    infoPlistPath = path / 'Info.plist'
    with open(str(infoPlistPath.resolve()), 'rb') as infoPlistFile:
        infoPlist = plistlib.load(infoPlistFile)
    
    bundle_id = infoPlist['CFBundleIdentifier']
    app_name = infoPlist.get('CFBundleDisplayName', infoPlist.get('CFBundleName', infoPlist['CFBundleIdentifier']))
    print(f'analyzing {app_name} at {path.name}')
    results['app_name'] = app_name
    results['bundle_id'] = bundle_id
    results['sdk'] = infoPlist.get('DTSDKName')
    results['deployment_target'] = infoPlist.get('MinimumOSVersion')
    text = get_text_of_executable(path)
    classes = class_dump(text)
    results['swift_version'] = get_swift_version(text)
    results["uses_swift"] = results["swift_version"] != "not swift"
    executable = find_executable_in(path)
    results['executable'] = executable.name
    save_to_file(text, f"{app_name}.m", app_name)
    results['percentage_swift'] = percentage_classes_in_swift(classes, app_name)
    results['main_binary_uses_swift'] = results['percentage_swift'] > 0
    results['percentage_swift'] = "{:.1f}".format(results['percentage_swift']  * 100)
    return results


apps = [path for path in Path.cwd().iterdir() if path.suffix == '.app']

with open('results.csv', mode='w', newline='') as csv_file:
    fieldnames = ['app_name', 'bundle_id', 'sdk', 'deployment_target','uses_swift', 'swift_version', 'main_binary_uses_swift', 'percentage_swift', 'executable']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()    
    writer.writerows(map(analyze_app, apps))
