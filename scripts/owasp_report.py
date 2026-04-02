import json
import os

input_file = "writable-reports/dependency-check-report.json"
output_file = "writable-reports/final-report.html"

# Ensure directory exists
os.makedirs("writable-reports", exist_ok=True)

def map_severity(score):
    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"

def severity_color(sev):
    return {
        "Critical": "#ff4d4d",
        "High": "#ff944d",
        "Medium": "#ffd24d",
        "Low": "#66cc66"
    }.get(sev, "#ffffff")

with open(input_file) as f:
    data = json.load(f)

html = """
<!DOCTYPE html>
<html>
<head>
<title>OWASP Vulnerability Report</title>
<style>
body { font-family: Arial; background:#0f172a; color:#e2e8f0; }
h1 { text-align:center; }
table { width:100%; border-collapse: collapse; margin-top:20px; }
th, td { padding:10px; border:1px solid #334155; }
th { background:#1e293b; }
</style>
</head>
<body>

<h1>🔐 OWASP Vulnerability Report</h1>

<table>
<tr>
<th>Name</th>
<th>OWASP</th>
<th>File</th>
<th>Severity</th>
<th>Description</th>
<th>Impact</th>
<th>Fix</th>
</tr>
"""

for dep in data.get("dependencies", []):
    for vuln in dep.get("vulnerabilities", []):

        name = vuln.get("name", "Unknown")
        severity = map_severity(vuln.get("cvssScore", 0))
        description = vuln.get("description", "N/A")

        html += f"""
        <tr>
        <td>{name}</td>
        <td>A06: Vulnerable Components</td>
        <td>{dep.get('fileName')}</td>
        <td style="background:{severity_color(severity)}; color:black;"><b>{severity}</b></td>
        <td>{description}</td>
        <td>Remote code execution / data leak risk</td>
        <td>Upgrade dependency / npm audit fix</td>
        </tr>
        """

html += """
</table>
</body>
</html>
"""

with open(output_file, "w") as f:
    f.write(html)

print("✅ HTML report generated:", output_file)
