import json
import winreg

registry = {}

key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")

i = 0
while True:
    try:
        name, value, _ = winreg.EnumValue(key, i)
        registry[name] = value
        i += 1
    except OSError:
        break

    winreg.CloseKey(key)

with open("baseline/registry_baseline.json", "w") as file:
    json.dump(registry, file, indent=4)

    print("Baseline Created Successfully.")