# parse.py - Windows Log Parser and Analyzer

A Python-based tool for parsing, filtering, and analyzing Windows Security and Sysmon event logs from CSV files. Supports advanced filtering by date range and string content, with output in multiple formats including interactive HTML reports.

## Features

- **Multi-Format Log Support**: Parse both Windows Security EventID=4688 and Sysmon EventID=1 events from the same CSV file
- **Field Aliasing**: Unified field names work across different log formats (e.g., `ProcessPath` works for both Sysmon's `Image` and Security's `New Process Name`)
- **Advanced Filtering**:
  - Filter by string content (case-insensitive substring matching)
  - Filter by date range (`--from-date` to `--to-date`)
  - Combine multiple filters
- **Flexible Grouping**: Group and aggregate logs by one or more fields
- **Automatic Metadata Extraction**: Extracts EventID, TimeGenerated, OriginatingComputer, Computer, Domain, Source, and other metadata
- **Multiple Output Formats**:
  - Table format (terminal-friendly, values truncated for readability)
  - Vertical format (detailed key:value block display)
  - Interactive HTML report with context menu (delete rows, move to top)
- **Space Preservation**: HTML output preserves all whitespace in log data
- **Summary Statistics**: HTML reports include total log count, unique combinations, and per-field analysis

## Requirements

- Python 3.6+
- Standard library only (no external dependencies required)

## Installation

1. Ensure Python 3.6+ is installed
2. Place `parse.py` in your working directory or add its location to your PATH

## Command-Line Usage

### Basic Syntax

```bash
python parse.py <input_csv> -g <field_names> [options]
```

### Required Arguments

| Argument | Description |
|----------|-------------|
| `input_csv` | Path to the input CSV file containing log data |
| `-g, --group-by` | Comma-separated field names to group/aggregate by (e.g., `EventID,ProcessPath`) |

### Optional Arguments

| Argument | Description |
|----------|-------------|
| `-f, --format` | Output format: `table` (default), `vertical`, or `html` |
| `-o, --output` | Output file path. For HTML format, use `.html` extension |
| `--filter` | Filter logs to keep only those containing specified string (case-insensitive) |
| `--from-date` | Filter logs from this date onwards (format: `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`) |
| `--to-date` | Filter logs up to this date (format: `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`) |
| `-c, --clean` | Produce clean CSV output only (extracts Message payloads without field analysis) |

## Output Formats

### Table Format (Default)

Terminal-friendly format with columns, values truncated for readability:

```
EventID | ProcessPath                      | Count
--------|----------------------------------|-------
4688    | C:\Windows\System32\powershel... | 42
1       | C:\Program Files\curl.exe        | 28
```

### Vertical Format

Detailed block format with complete values shown:

```
[1] Count: 42
    EventID: 4688
    ProcessPath: C:\Windows\System32\powershell.exe
```

### HTML Format

Interactive HTML report with:
- Summary section (log file, fields analyzed, total count, unique combinations)
- Sortable results table
- Right-click context menu on rows (delete with fade animation, move to top)
- Whitespace preservation for detailed log inspection
- Highlighting for high-count entries (≥10)

## Field Aliasing Reference

Use these unified field names across both Sysmon and Security event formats:

### Process-Related Fields

| Alias | Sysmon Field | Security Field |
|-------|--------------|----------------|
| `ProcessPath` | Image | New Process Name |
| `ProcessCmdLine` | CommandLine | Process Command Line |
| `ParentProcessPath` | ParentImage | Creator Process Name |
| `ParentProcessCmdLine` | ParentCommandLine | Creator Process Command Line |

### User-Related Fields

| Alias | Sysmon Field | Security Field |
|-------|--------------|----------------|
| `UserAccount` | User | Account Name |

### Example
Both of these commands work identically across log types:
```bash
python parse.py logs.csv -g ProcessPath,UserAccount
python parse.py logs.csv -g Image,ProcessCmdLine -g User  # Also works with original names
```

## Supported Log Formats

### Windows Security EventID=4688

Windows Security process creation events with:
- Double-space separators between sections
- Creator Subject section containing Security ID
- Fields like "New Process Name", "Process Command Line", "Account Name"

### Sysmon EventID=1

Sysmon process creation events with:
- Single-space separators between key:value pairs
- Compact field names (Image, CommandLine, User, etc.)
- All fields typically well-populated

### Metadata Fields

Both formats automatically extract these metadata fields:
- EventID
- TimeGenerated
- OriginatingComputer
- Computer
- Domain
- Source
- AgentLogFile
- Security ID (Windows Security only)

Both formats can coexist in the same CSV file and will be parsed correctly.

## Usage Examples

### Basic: Group by single field

```bash
python parse.py events.csv -g EventID
```

Group all logs by EventID and display counts in default table format.

### Group by multiple fields

```bash
python parse.py t1105.csv -g EventID,ProcessPath,UserAccount
```

Show combinations of event type, process path, and user account with occurrence counts.

### Filter by string content

```bash
python parse.py events.csv -g EventID,ProcessPath --filter powershell
```

Show only logs containing "powershell" (case-insensitive).

### Filter by date range

```bash
python parse.py events.csv -g EventID,ProcessPath --from-date 2026-03-24 --to-date 2026-03-25
```

Show only logs from March 24-25, 2026.

### Filter by date and string combined

```bash
python parse.py events.csv -g EventID,ProcessPath --from-date 2026-03-24 --to-date 2026-03-25 --filter curl
```

Show logs from specific date range containing "curl".

### Generate HTML report with specific filtering

```bash
python parse.py t1105.csv -g EventID,ProcessPath,ProcessCmdLine -f html -o report.html --from-date 2026-01-01 --filter cmd.exe
```

Generate interactive HTML report showing cmd.exe execution patterns since January 1, 2026.

### Use field aliases across formats

```bash
python parse.py mixed_logs.csv -g ProcessPath,ParentProcessPath,UserAccount -f vertical
```

Works seamlessly with both Sysmon and Security events in the same file, showing process-parent-user relationships.

### Vertical format for detailed inspection

```bash
python parse.py events.csv -g EventID,ProcessPath,ProcessCmdLine -f vertical
```

Display all values without truncation in block format.

### Extract and clean payload data

```bash
python parse.py events.csv --clean -o cleaned.csv
```

Extract Message payloads from CSV without any field analysis (useful for further processing).

## Date Format Specifications

Dates in `--from-date` and `--to-date` parameters accept:

- **Date only**: `YYYY-MM-DD` (treated as 00:00:00 to 23:59:59)
  - Example: `--from-date 2026-03-24`

- **Date with time**: `YYYY-MM-DD HH:MM:SS`
  - Example: `--from-date "2026-03-24 14:30:00"`
  - Example: `--to-date "2026-03-24 16:45:59"`

Note: Time portion is optional but allows precise filtering when needed.

## Output Examples

### Terminal Table Output

```
Fields grouped: EventID, ProcessPath (4 unique combinations)

EventID | ProcessPath                            | Count
--------|----------------------------------------|-------
1       | C:\Windows\System32\svchost.exe       | 24
1       | C:\Program Files\Git\usr\bin\grep.exe | 18
4688    | C:\Windows\System32\cmd.exe           | 12
4688    | C:\Windows\System32\powershell.exe    | 8
```

### HTML Report Features

- **Summary Section**: Displays log filename, grouped fields, total log count, and unique combinations
- **Interactive Table**: Up to 50 rows displayed with hover highlighting
- **Right-Click Menu**: Delete rows (with fade animation) or move to top
- **Visual Indicators**: Rows with 10+ occurrences highlighted in yellow
- **Whitespace Preserved**: Original spacing in command lines and paths maintained

## Practical Scenarios

### Detect suspicious process patterns
```bash
python parse.py events.csv -g ProcessPath,ProcessCmdLine --filter "/c " -f html -o suspicious.html
```

### Track lateral movement
```bash
python parse.py events.csv -g OriginatingComputer,ProcessPath,UserAccount --from-date 2026-03-20 --to-date 2026-03-25 -f html -o lateral_movement.html
```

### Analyze specific user activities
```bash
python parse.py events.csv -g EventID,ProcessPath,ProcessCmdLine --filter "contoso\jsmith" -f vertical
```

### Timeline of specific process
```bash
python parse.py events.csv -g TimeGenerated,ProcessCmdLine --filter "curl.exe" -f vertical
```

## Troubleshooting

### "Unable to parse date" error
Ensure date format is exactly `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`. Do not use other separators or formats.

### Missing TimeGenerated in filter results
The `--from-date` and `--to-date` filters require TimeGenerated metadata. Ensure your CSV contains TimeGenerated field in the payload.

### Empty or `<missing>` values in output
Fields may not exist in all log entries. This is normal for:
- EventID=1 logs missing "Creator Process Name" (use `ParentProcessPath` alias instead)
- EventID=4688 logs with empty "Process Command Line"
- Format-specific fields not present in other formats

Use field aliases for better cross-format compatibility.

### No results with filters
Verify:
1. Date range falls within your log timestamps
2. String filter matches actual log content (case-insensitive but must match content exactly)
3. Combine filters with `--filter` to narrow results
4. Check HTML report in browser for better inspection

## Technical Notes

- **Memory**: Loads entire CSV into memory; large files (>100K rows) may require system RAM
- **Performance**: String filtering is case-insensitive and searches entire row content
- **Date Conversion**: Uses Unix epoch (seconds since 1970-01-01 UTC) for date comparison
- **Encoding**: Assumes UTF-8 encoding for input CSV files
- **CSV Format**: Expects payloads in third column (index 2) or last column

## Advanced Usage

### Piping multiple analyses

```bash
# Generate report for specific date
python parse.py events.csv -g EventID,ProcessPath --from-date 2026-03-24 --to-date 2026-03-24 -f table
# Then refine by filtering results
python parse.py events.csv -g EventID,ProcessPath --from-date 2026-03-24 -f html --filter "notepad" -o notepad_activity.html
```

### Field resolution order

When using field names:
1. Direct field match (exact case)
2. Case-insensitive field match
3. Alias lookup (if field is in FIELD_ALIASES)
4. Display `<missing>` if all lookups fail

This ensures flexibility across different log formats and field name variations.

## Contributing & Modifications

The script is self-contained and can be easily extended:

- **Add new aliases**: Modify `FIELD_ALIASES` dictionary in the script header
- **New output formats**: Create functions similar to `format_vertical()` or `format_truncated_table()`
- **Custom filters**: Extend the filtering logic in `summarize_csv_field_multi()`

## License

Use as needed for log analysis and incident response activities.
