import csv
import sys 
from collections import defaultdict
from datetime import datetime
import time

# Field name aliases for cross-format consistency (Sysmon vs Windows Security)
# Maps user-friendly alias to list of actual field names to check (in priority order)
FIELD_ALIASES = {
    'ProcessPath': ['Image', 'New Process Name'],
    'ProcessCmdLine': ['CommandLine', 'Process Command Line'],
    'ParentProcessPath': ['ParentImage', 'Creator Process Name'],
    'ParentProcessCmdLine': ['ParentCommandLine', 'Creator Process Command Line'],
    'UserAccount': ['User', 'Account Name'],
}

def parse(folder:str ,filename: str, ignore_prefix: str):
    result = []
    with open(filename, "r", encoding='utf-8') as file:
        for line in file.readlines():
            if ignore_prefix not in line:
                result.append(line)
    with open("clean.csv","w") as file:
        file.writelines(result)

def process_csv_style(input_file, output_file):
    processed_rows = []

    try:
        with open(input_file, 'r', encoding='utf-8') as infile:
            reader = csv.reader(infile, skipinitialspace=True)
            # skip header / first line
            next(reader, None)
            for row in reader:
                if row and len(row) >= 3:
                    # keep only the 3rd field from each CSV record
                    processed_rows.append(row[2])

        # write cleaned payload lines
        with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
            for value in processed_rows:
                outfile.write(value + '\n')
        print("Done! CSV cleaned successfully.")

    except Exception as e:
        print(f"Error: {e}")


def parse_date_to_timestamp(date_str):
    """Convert date string to Unix timestamp. Accepts formats: YYYY-MM-DD, YYYY-MM-DD HH:MM:SS"""
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d',
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            return int(dt.timestamp())
        except ValueError:
            continue
    raise ValueError(f"Unable to parse date: {date_str}. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")


def is_within_date_range(time_generated_str, from_timestamp, to_timestamp):
    """Check if TimeGenerated (as string or epoch seconds) falls within date range."""
    try:
        # TimeGenerated is typically an epoch timestamp as string
        ts = int(time_generated_str)
        return from_timestamp <= ts <= to_timestamp
    except (ValueError, TypeError):
        return False


def parse_event_payload(payload):
    """Parse `key: value` pairs from the Message field content only.
    Dynamically extracts any key found in the format 'Key: Value'"""
    import re
    result = {}
    
    # First extract tab-separated fields at the beginning (metadata fields like EventID, OriginatingComputer, etc.)
    for part in payload.split('\t'):
        item = part.strip()
        if not item:
            continue
        if '=' in item:
            key, value = item.split('=', 1)
            key = key.strip()
            value = value.strip()
            # Capture metadata fields from tab-separated part (exclude User since message payload has actual user info)
            if key in ('EventID', 'OriginatingComputer', 'Computer', 'Domain', 'Source', 'AgentLogFile', 'TimeGenerated'):
                result[key] = value
    
    # Extract the Message field content
    if 'Message=' not in payload:
        return result
    
    # Find where Message= starts
    msg_idx = payload.index('Message=')
    message_content = payload[msg_idx + len('Message='):].strip()
    
    # Handle Security EventID=4688 format with "Creator Subject:" section
    creator_subject_match = re.search(r'Creator Subject:\s+(.+?)(?=\s{2,}Target Subject:|$)', message_content)
    if creator_subject_match:
        creator_subject = creator_subject_match.group(1)
        # Extract Security ID from Creator Subject
        security_id_match = re.search(r'Security ID:\s+([^\s]+(?:\s+[^\s]+)*?)\s{2,}(?:Account Name:|$)', creator_subject)
        if security_id_match:
            result['Security ID'] = security_id_match.group(1).strip()
    
    # Pattern for key: value pairs
    # Handles both formats:
    # - Security events with double-space separators
    # - Sysmon events with single-space separators
    # Using \s* to allow empty values, and \s* in lookahead to handle fields with no values
    pattern = r'([A-Z][A-Za-z0-9 ]*?):\s*(.+?)(?=\s+[A-Z][\w\s]*?:\s*|$)'
    
    matches = re.finditer(pattern, message_content)
    for match in matches:
        key = match.group(1).strip()
        value = match.group(2).strip()
        
        # Skip section headers and already-captured values
        if key in ('Creator Subject', 'Target Subject', 'Process Information', 'Message', 'Process Create', 'RuleName'):
            continue
        
        if key and value and key not in result:
            result[key] = value
    
    return result


def resolve_field_value(field_name, kv_dict):
    """
    Resolve field value from parsed event data, checking aliases if needed.
    Returns (value, field_used) tuple, or (None, None) if not found.
    """
    # Check if field exists directly
    if field_name in kv_dict:
        return kv_dict[field_name], field_name
    
    # Check case-insensitive match
    lower_field = field_name.lower()
    for k, v in kv_dict.items():
        if k.lower() == lower_field:
            return v, k
    
    # Check if it's an alias and try the actual field names
    if field_name in FIELD_ALIASES:
        for actual_field in FIELD_ALIASES[field_name]:
            if actual_field in kv_dict:
                return kv_dict[actual_field], actual_field
            # Also check case-insensitive
            for k in kv_dict:
                if k.lower() == actual_field.lower():
                    return kv_dict[k], k
    
    return None, None


def summarize_csv_field(input_file, field_name, output_file=None, no_header=False):
    """Summarize distinct values of `field_name` in CSV file logs."""
    counts = {}

    with open(input_file, 'r', encoding='utf-8', newline='') as infile:
        reader = csv.reader(infile, skipinitialspace=True)

        header = None
        if not no_header:
            try:
                header = next(reader)
            except StopIteration:
                print('No data in file.')
                return

        # if header has requested field, use it directly
        direct_index = None
        if header and field_name in header:
            direct_index = header.index(field_name)

        for row in reader:
            if not row:
                continue

            if direct_index is not None and direct_index < len(row):
                value = row[direct_index].strip()
            else:
                value = None
                candidates = []
                # common last columns in your sample files (third col contains readable payload)
                if len(row) >= 3:
                    candidates.append(row[2])
                if len(row) >= 4:
                    candidates.append(row[-2])
                candidates.append(row[-1])

                for payload in candidates:
                    kv = parse_event_payload(payload)
                    if not kv:
                        continue

                    value, _ = resolve_field_value(field_name, kv)
                    if value is not None:
                        break

                if value is None:
                    continue

            if value == '':
                value = '<empty>'
            counts[value] = counts.get(value, 0) + 1

    sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)

    if output_file:
        with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
            writer = csv.writer(outfile)
            writer.writerow([field_name, 'count'])
            for value, count in sorted_counts:
                writer.writerow([value, count])

    print(f"Summary for {field_name} ({len(sorted_counts)} unique values):")
    for value, count in sorted_counts[:50]:
        print(f"{count}\t{value}")


def truncate_path(path, max_length=60):
    """Truncate long paths with ellipsis in the middle."""
    if len(path) <= max_length:
        return path
    # Show start and end of path
    left_len = (max_length - 3) // 2
    right_len = max_length - 3 - left_len
    return path[:left_len] + '...' + path[-right_len:]


def format_vertical(field_names, sorted_counts, total_combos):
    """Display results in vertical block format."""
    field_str = ' + '.join(field_names)
    print(f"\nSummary for {field_str} ({total_combos} unique combinations):")
    print()
    
    for idx, (combo, count) in enumerate(sorted_counts[:50], 1):
        print(f"[{idx}] Count: {count}")
        for field_name, value in zip(field_names, combo):
            print(f"    {field_name}: {value}")
        print()


def format_truncated_table(field_names, header_cols, sorted_counts, total_combos, max_col_width=40):
    """Display results as a table with columns, truncating values to fit column width."""
    field_str = ' + '.join(field_names)
    print(f"\nSummary for {field_str} ({total_combos} unique combinations):")
    
    # Set column widths optimized for 80-char terminal
    col_widths = {
        'EventID': 6,
        'Image': 20,
        'TargetObject': 38,
        'count': 5
    }
    
    # Use specific widths if known, else use default
    actual_widths = []
    for col_name in header_cols:
        actual_widths.append(col_widths.get(col_name, max_col_width))
    
    # Print header
    header_parts = []
    for i, col in enumerate(header_cols):
        header_parts.append(col[:actual_widths[i]].ljust(actual_widths[i]))
    header_line = ' | '.join(header_parts)
    print(header_line)
    print('-' * len(header_line))
    
    # Print rows with truncated values
    for combo, count in sorted_counts[:50]:
        row_parts = []
        for i, v in enumerate(list(combo) + [count]):
            val_str = str(v)
            # Simple truncation to fit column width
            truncated = val_str[:actual_widths[i]] if len(val_str) > actual_widths[i] else val_str
            row_parts.append(truncated.ljust(actual_widths[i]))
        
        row_line = ' | '.join(row_parts)
        print(row_line)


def format_html(field_names, sorted_counts, total_combos, output_file):
    """Generate an HTML report with formatted results."""
    # Calculate total log count
    total_logs = sum(count for _, count in sorted_counts)
    
    html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Log Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #333; }
        .summary { background: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background: #4CAF50; color: white; padding: 12px; text-align: left; font-weight: bold; }
        td { padding: 12px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f9f9f9; }
        tbody tr { cursor: context-menu; }
        .count { text-align: center; font-weight: bold; }
        .detail { word-break: break-all; font-size: 0.9em; white-space: pre-wrap; }
        .high-count { background: #fff3cd; }
        .context-menu {
            display: none;
            position: fixed;
            background: white;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            z-index: 10000;
            min-width: 150px;
        }
        .context-menu.show { display: block; }
        .context-menu-item {
            padding: 10px 15px;
            cursor: pointer;
            user-select: none;
        }
        .context-menu-item:hover {
            background: #f0f0f0;
        }
    </style>
    <script>
        let contextMenu = null;
        let selectedRow = null;
        
        function setupContextMenu() {
            // Create context menu element
            contextMenu = document.createElement('div');
            contextMenu.className = 'context-menu';
            contextMenu.innerHTML = `
                <div class="context-menu-item" onclick="deleteRow()">Delete</div>
                <div class="context-menu-item" onclick="moveToTop()">Move to Top</div>
            `;
            document.body.appendChild(contextMenu);
            
            // Close menu when clicking elsewhere
            document.addEventListener('click', hideContextMenu);
            
            // Setup right-click on table rows
            const rows = document.querySelectorAll('tbody tr');
            rows.forEach(row => {
                row.addEventListener('contextmenu', (e) => {
                    e.preventDefault();
                    selectedRow = row;
                    showContextMenu(e.clientX, e.clientY);
                });
            });
        }
        
        function showContextMenu(x, y) {
            contextMenu.style.left = x + 'px';
            contextMenu.style.top = y + 'px';
            contextMenu.classList.add('show');
        }
        
        function hideContextMenu() {
            if (contextMenu) {
                contextMenu.classList.remove('show');
            }
        }
        
        function deleteRow() {
            if (selectedRow) {
                selectedRow.style.transition = 'opacity 0.3s ease';
                selectedRow.style.opacity = '0';
                setTimeout(function() {
                    selectedRow.remove();
                }, 300);
            }
            hideContextMenu();
        }
        
        function moveToTop() {
            if (selectedRow) {
                const tbody = selectedRow.parentNode;
                tbody.insertBefore(selectedRow, tbody.firstChild);
            }
            hideContextMenu();
        }
        
        document.addEventListener('DOMContentLoaded', setupContextMenu);
    </script>
</head>
<body>
    <h1>Log Analysis Report</h1>
    <div class="summary">
        <p><strong>Log file:</strong> """ + sys.argv[1] + """</p>
        <p><strong>Fields grouped:</strong> """ + ', '.join(field_names) + """</p>
        <p><strong>Total log count:</strong> """ + str(total_logs) + """</p>
        <p><strong>Unique combinations:</strong> """ + str(total_combos) + """</p>
    </div>
    <table>
        <thead>
            <tr>"""
    
    for field_name in field_names:
        html += f"\n                <th>{field_name}</th>"
    html += "\n                <th class='count'>Count</th>\n            </tr>\n        </thead>\n        <tbody>\n"
    
    for combo, count in sorted_counts[:50]:
        is_high = count >= 10
        row_class = ' class="high-count"' if is_high else ''
        html += f"            <tr{row_class}>\n"
        for value in combo:
            html += f"                <td class='detail'>{value}</td>\n"
        html += f"                <td class='count'>{count}</td>\n            </tr>\n"
    
    html += """        </tbody>
    </table>
</body>
</html>"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"\nHTML report saved to: {output_file}")


def summarize_csv_field_multi(input_file, field_names, output_file=None, no_header=False, format_type='table', filter_string=None, from_date=None, to_date=None):
    """Summarize logs grouped by combination of multiple fields. Always includes EventID."""
    counts = defaultdict(int)
    
    # Convert date strings to timestamps if provided
    from_timestamp = None
    to_timestamp = None
    if from_date:
        from_timestamp = parse_date_to_timestamp(from_date)
        print(f"Filtering from: {from_date} (timestamp: {from_timestamp})")
    if to_date:
        to_timestamp = parse_date_to_timestamp(to_date)
        # Set to end of day if only date provided
        if ' ' not in to_date.strip():
            to_timestamp += 86399  # Add 23:59:59
        print(f"Filtering to: {to_date} (timestamp: {to_timestamp})")
    
    # Always include EventID if not already in the field list
    field_names = list(field_names)
    if 'EventID' not in field_names:
        field_names.insert(0, 'EventID')
    
    with open(input_file, 'r', encoding='utf-8', newline='') as infile:
        reader = csv.reader(infile, skipinitialspace=True)

        header = None
        if not no_header:
            try:
                header = next(reader)
            except StopIteration:
                print('No data in file.')
                return

        # build field indices for direct CSV columns
        direct_indices = {}
        for field_name in field_names:
            if header and field_name in header:
                direct_indices[field_name] = header.index(field_name)

        for row in reader:
            if not row:
                continue
            
            # Parse payload to extract TimeGenerated and other fields
            payload = None
            if len(row) >= 3:
                payload = row[2]
            elif len(row) >= 1:
                payload = row[-1]
            
            # Always parse the payload first to get TimeGenerated for date filtering
            parsed_data = {}
            if payload:
                parsed_data = parse_event_payload(payload)
            
            # Apply date range filter if specified
            if from_timestamp or to_timestamp:
                if 'TimeGenerated' in parsed_data:
                    time_gen_val = parsed_data['TimeGenerated']
                    if not is_within_date_range(time_gen_val, from_timestamp or 0, to_timestamp or 9999999999):
                        continue
                else:
                    # Skip if date filtering requested but TimeGenerated not found
                    continue
            
            # Apply string filter if specified
            if filter_string:
                # Check if the filter string exists anywhere in this row
                row_str = '\t'.join(row)
                if filter_string.lower() not in row_str.lower():
                    continue

            values = []
            for field_name in field_names:
                value = None

                if field_name in direct_indices and direct_indices[field_name] < len(row):
                    value = row[direct_indices[field_name]].strip()
                else:
                    # Use already-parsed data or parse again if needed
                    if field_name in parsed_data:
                        value = parsed_data[field_name]
                    else:
                        # Try resolving via aliases
                        value, _ = resolve_field_value(field_name, parsed_data)

                if value is None:
                    value = '<missing>'
                values.append(value)

            combo_key = tuple(values)
            counts[combo_key] += 1

    sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)

    # build header
    header_cols = list(field_names) + ['count']
    
    if output_file and not output_file.endswith('.html'):
        with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
            writer = csv.writer(outfile)
            writer.writerow(header_cols)
            for combo, count in sorted_counts:
                writer.writerow(list(combo) + [count])
        print(f"CSV results saved to: {output_file}")

    # Display results based on format_type
    if format_type == 'vertical':
        format_vertical(field_names, sorted_counts, len(sorted_counts))
    elif format_type == 'html':
        if output_file:
            format_html(field_names, sorted_counts, len(sorted_counts), output_file)
        else:
            html_file = 'report.html'
            format_html(field_names, sorted_counts, len(sorted_counts), html_file)
    else:  # 'table' (default) or 'truncated'
        format_truncated_table(field_names, header_cols, sorted_counts, len(sorted_counts))


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Parse and summarize CSV log events.')
    parser.add_argument('input', help='Input CSV file path')
    parser.add_argument('-g', '--group-by', required=False, help='Comma-separated list of field names to group/aggregate by together (e.g. EventID,ProcessPath)')
    parser.add_argument('-c', '--clean', action='store_true', help='Produce clean CSV text output only (no field summary)')
    parser.add_argument('-o', '--output', help='Optional output file path')
    parser.add_argument('-f', '--format', choices=['table', 'vertical', 'html'], default='table',
                        help='Output format: table (default, truncated for readability), vertical (key:value blocks), or html (HTML report)')
    parser.add_argument('--filter', help='Filter logs to keep only those containing specified string (case-insensitive)')
    parser.add_argument('--from-date', help='Filter logs from this date onwards (format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)')
    parser.add_argument('--to-date', help='Filter logs up to this date (format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)')
    args = parser.parse_args()

    if args.clean:
        out = args.output or 'clean.csv'
        process_csv_style(args.input, out)
    elif args.group_by:
        # multi-field grouping mode
        group_fields = [x.strip() for x in args.group_by.split(',') if x.strip()]
        summarize_csv_field_multi(args.input, group_fields, output_file=args.output, format_type=args.format, filter_string=args.filter, from_date=args.from_date, to_date=args.to_date)
    else:
        parser.error('required: -g/--group-by (or use --clean for clean-only mode)')


