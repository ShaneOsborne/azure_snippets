/*
.SYNOPSIS
  Detects query performance regressions for DemoTable queries via Query Store.

.DESCRIPTION
  Checks sys.query_store_runtime_stats for queries referencing DemoTable where
  average duration has regressed beyond the last execution time threshold.
  Throws error 50006 if a regression is detected.

.NOTES
  Query Store must be enabled in the target database.
*/

-- Example: fail if average duration regresses beyond threshold
IF EXISTS (
    SELECT 1
    FROM sys.query_store_runtime_stats rs
    JOIN sys.query_store_plan p ON rs.plan_id = p.plan_id
    JOIN sys.query_store_query q ON p.query_id = q.query_id
    WHERE q.query_sql_text LIKE '%DemoTable%'
      AND rs.avg_duration > 2 * rs.last_execution_time
)
    THROW 50006, 'Query performance regression detected', 1;
