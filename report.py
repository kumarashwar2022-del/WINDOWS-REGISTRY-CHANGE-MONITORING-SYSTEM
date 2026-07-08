import os

log_file = "logs/registry_logs.txt"
report_file = "reports/report.txt"

if not os.path.exists(log_file):
    print("Log file not found!")
    exit()

with open(log_file, "r") as file:
    logs = file.readlines()

with open(report_file, "w") as report:

    report.write("=" * 40 + "\n")
    report.write(" Registry Monitoring Report\n")
    report.write("=" * 40 + "\n\n")

    report.write(f"Total Events : {len(logs)}\n\n")

    report.write("Entries:\n\n")

    for line in logs:
        report.write(line)

    report.write("\n")
    report.write("=" * 40 + "\n")
    report.write("End of Report\n")
    report.write("=" * 40 + "\n")

print("Report Generated Successfully!")