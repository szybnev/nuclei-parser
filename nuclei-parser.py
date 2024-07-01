import argparse
import json
import sys
from tabulate import tabulate

# Определяем порядок сортировки
severity_order = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
    "unknown": 6
}


def severity_key(issue):
    severity = issue.get('info', {}).get('severity', 'unknown').lower()
    return severity_order.get(severity, severity_order['unknown'])


def generate_html(issue_obj, filename='output.html'):
    html_content = """
    <html>
    <head>
        <title>Nuclei Scan Result</title>
        <style>
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                border: 1px solid black;
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
        </style>
    </head>
    <body>
        <h1>Scan Result</h1>
        <table>
            <tr>
                <th>Template ID</th>
                <th>Name</th>
                <th>Severity</th>
                <th>Host</th>
                <th>Matched At</th>
            </tr>
    """
    for issue in issue_obj:
        html_content += f"""
            <tr>
                <td>{issue.get('template-id')}</td>
                <td>{issue.get('info', {}).get('name')}</td>
                <td>{issue.get('info', {}).get('severity')}</td>
                <td>{issue.get('host')}</td>
                <td>{issue.get('matched-at')}</td>
            </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    with open(filename, 'w') as f:
        f.write(html_content)


def print_table(issue_obj):
    headers = ["Template ID", "Name", "Severity", "Host", "Matched At"]
    table = []
    for issue in issue_obj:
        row = [
            issue.get('template-id'),
            issue.get('info', {}).get('name'),
            issue.get('info', {}).get('severity'),
            issue.get('host'),
            issue.get('matched-at')
        ]
        table.append(row)
    print(tabulate(table, headers, tablefmt="grid"))


def main():
    parser = argparse.ArgumentParser(description='Nuclei Scan Tool')
    parser.add_argument('--html', action='store_true', help='Generate HTML output instead of terminal output')
    parser.add_argument('-d', '--data', type=str, required=True, help='Path to the JSON data file')
    parser.add_argument('-s', '--severity', type=str, help='Filter results by severity (comma separated)')
    args = parser.parse_args()

    if args.severity:
        severities = args.severity.split(',')
        severities = [s.strip() for s in severities]
    else:
        severities = []

    issues = []
    try:
        with open(args.data, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    issue = json.loads(line.strip())
                    issues.append(issue)
                except json.JSONDecodeError as e:
                    print(f"Error parsing line: {line}\n{e}", file=sys.stderr)
                    continue
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(issues)} issues from the data file.")

    # Фильтрация по критичности
    if severities:
        filtered_issues = [issue for issue in issues if issue.get('info', {}).get('severity') in severities]
        print(f"Filtered issues: {len(filtered_issues)} with severities {', '.join(severities)}")
    else:
        filtered_issues = issues

    # Сортировка по критичности
    sorted_issues = sorted(filtered_issues, key=severity_key)

    # Проверка наличия ключа 'matched-at' и соответствия
    if sorted_issues:
        matched_at = sorted_issues[0].get('matched-at')
        if matched_at:
            # Проверка наличия параметра --html
            if args.html:
                generate_html(sorted_issues)
                print("HTML generated")
            else:
                print_table(sorted_issues)
        else:
            error_message = {"error": "Key 'matched-at' not found"}
            if args.html:
                generate_html([error_message])
                print("HTML generated")
            else:
                print_table([error_message])
    else:
        print("No data matching the specified severity.", file=sys.stderr)


if __name__ == '__main__':
    main()
