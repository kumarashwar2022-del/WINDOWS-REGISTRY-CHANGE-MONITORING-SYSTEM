from datetime import datetime
import json
import time
import winreg


def read_registry_key():
    current_registry = {}

    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run"
    )

    i = 0

    while True:
        try:
            value_name, value_data, _ = winreg.EnumValue(key, i)
            current_registry[value_name] = value_data
            i += 1

        except OSError:
            break

    winreg.CloseKey(key)

    return current_registry


with open("baseline/registry_baseline.json", "r") as file:
    baseline_data = json.load(file)

    suspicious_keywords = [
    "powershell",
    "cmd",
    "temp",
    "appdata",
    ".vbs",
    ".bat",
    ".exe"]

print("Registry Monitoring Started...\n")

already_reported = set()

while True:

    print("Checking Registry...")

    current_registry = read_registry_key()

    for name in current_registry:

        if name not in baseline_data:

            if name not in already_reported:

                print(f"[{datetime.now()}] New Entry Found: {name}")

                value = current_registry[name]

for keyword in suspicious_keywords:

    if keyword.lower() in value.lower():

        print("⚠ Suspicious Registry Entry Detected!")
        print("Value:", value)

        break

    with open("logs/registry_logs.txt", "a") as log_file:
                    log_file.write(f"{datetime.now()} | New Entry | {name}\n")


    time.sleep(10)