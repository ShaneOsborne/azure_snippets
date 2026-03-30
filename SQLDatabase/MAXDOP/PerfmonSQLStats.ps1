<#
.SYNOPSIS
    Captures SQL Server and host PerfMon counters to CSV for MAXDOP baseline and test window analysis.

.DESCRIPTION
    Creates a temporary Windows Performance Monitor collector set (`MaxDopBaseline`) using `logman`,
    samples selected counters at a fixed interval, waits for the configured duration, and then stops
    and removes the collector set.

.NOTES
    - Run on the SQL Server host.
    - Typically requires local administrator rights for `logman create/start/stop/delete`.
    - Update output path, counters, and duration before execution.

.EXAMPLE
    .\PerfmonSQLStats.ps1
    Captures counters to C:\PerfLogs\maxdop_baseline.csv every 30 seconds for 48 hours.
#>

$Counters = @(
    '\Processor(_Total)\% Processor Time',
    '\Process(sqlservr)\% Processor Time',
    '\SQLServer:Wait Statistics\CXPACKET',
    '\SQLServer:Wait Statistics\CXCONSUMER',
    '\System\Processor Queue Length',
    '\SQLServer:SQL Statistics\Batch Requests/sec'
)
$Output = "C:\PerfLogs\maxdop_baseline.csv"
$SampleInterval = 30
$DurationHours = 48

# Create and start the counter set
logman create counter MaxDopBaseline -f csv -o $Output -c $Counters -si $SampleInterval
logman start MaxDopBaseline

# Sleep for the duration (or run as scheduled job)
Start-Sleep -Seconds ($DurationHours * 3600)

# Stop and delete the counter set
logman stop MaxDopBaseline
logman delete MaxDopBaseline
