import json

input_file = "reports/dependency-check-report.json"
output_file = "reports/final-report.txt"

with open(input_file) as f:
    data = json.load(f)

def map_severity(score):
    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"

with open(output_file, "w") as out:
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulnerabilities", []):
            
            name = vuln.get("name", "Unknown")
            severity = map_severity(vuln.get("cvssScore", 0))
            description = vuln.get("description", "N/A")

            out.write("--------------------------------------------------\n")
            out.write(f"Vulnerability Name: {name}\n")
            out.write(f"OWASP Category: A06: Vulnerable Components\n")
            out.write(f"Affected File: {dep.get('fileName')}\n")
            out.write(f"Severity: {severity}\n")
            out.write(f"Description: {description}\n")
            out.write(f"Business Impact: Remote code execution / data leak risk\n")
            out.write(f"Proof of Concept: npm audit\n")
            out.write(f"Recommended Fix: npm audit fix or upgrade dependency\n\n")
