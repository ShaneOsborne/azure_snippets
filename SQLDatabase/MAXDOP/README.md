# MAXDOP

Scripts to inventory SQL Server parallelism settings, extract Query Store CPU-heavy queries, run repeatable per-query MAXDOP tests, and optionally capture host PerfMon counters during baseline windows.

## Files

- `1.Inventory.sql`
  - Captures server/instance metadata and current parallelism settings.
  - Returns CPU, scheduler, and NUMA topology details used to scope MAXDOP decisions.

- `2.QueryStoreExtract.sql`
  - Retrieves top Query Store plans by average CPU time for a target database.
  - Optionally stages top rows in a temp table (`#qs_top`) for follow-on analysis.

- `3.PerQueryTestHarness.sql`
  - Executes a target query repeatedly across MAXDOP values (1, 2, 4, 8 by default).
  - Records duration per run and outputs summary statistics.
  - Optionally archives results to `dbo.MaxDopTestResults_Archive`.

- `PerfmonSQLStats.ps1`
  - Creates a temporary PerfMon data collector set using `logman`.
  - Captures SQL and host counters to CSV over a configurable duration.

## Prerequisites

### SQL scripts

- SQL Server permissions to query DMVs and Query Store views in target databases.
- Query Store enabled for databases where `2.QueryStoreExtract.sql` is executed.

### PowerShell script

- PowerShell 5.1+ or PowerShell 7+
- Local administrator rights (required for `logman create/start/stop/delete`)
- SQL Server host access (run directly on the SQL Server VM/host)

## Suggested Workflow

1. Run `1.Inventory.sql` in `master` to baseline instance settings and CPU/NUMA topology.
2. Run `2.QueryStoreExtract.sql` in each target database to identify CPU-expensive candidates.
3. For each candidate, set query text in `3.PerQueryTestHarness.sql` and run controlled tests.
4. Optionally run `PerfmonSQLStats.ps1` during baseline and test windows for host-side correlation.

## Notes

- Update placeholders before running:
  - `USE [YourDatabase]` in `2.QueryStoreExtract.sql`
  - `@sql` text in `3.PerQueryTestHarness.sql`
  - `$Output`, `$DurationHours`, and counters in `PerfmonSQLStats.ps1`
- This content is for testing and diagnostics guidance; validate results in your environment before changing production settings.