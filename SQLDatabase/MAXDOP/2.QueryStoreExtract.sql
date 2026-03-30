/*
.SYNOPSIS
    Extracts Query Store plans and query text to identify CPU-heavy query candidates.

.DESCRIPTION
    Pulls top queries ordered by average CPU time from Query Store views and optionally
    stages top rows in a temp table (`#qs_top`) for downstream review.

.USAGE
    1. Replace `USE [YourDatabase]` with the target database.
    2. Execute in the target database context.

.NOTES
    Query Store must be enabled in the target database.
*/

USE [YourDatabase];  -- replace with DB name
GO

-- Top 50 queries by average CPU time (Query Store)
SELECT TOP 50
    qsq.query_id,
    qst.query_sql_text,
    qsp.plan_id,
    qsp.count_executions,
    qsp.avg_duration,
    qsp.avg_cpu_time,
    qsp.avg_logical_io_reads
FROM sys.query_store_query qsq
JOIN sys.query_store_query_text qst ON qsq.query_text_id = qst.query_text_id
JOIN sys.query_store_plan qsp ON qsq.query_id = qsp.query_id
ORDER BY qsp.avg_cpu_time DESC;

-- Export Query Store rows to a table for later analysis (optional)
IF OBJECT_ID('tempdb..#qs_top') IS NOT NULL DROP TABLE #qs_top;
SELECT TOP 1000
    qsq.query_id, qst.query_sql_text, qsp.plan_id, qsp.count_executions, qsp.avg_duration, qsp.avg_cpu_time
INTO #qs_top
FROM sys.query_store_query qsq
JOIN sys.query_store_query_text qst ON qsq.query_text_id = qst.query_text_id
JOIN sys.query_store_plan qsp ON qsq.query_id = qsp.query_id
ORDER BY qsp.avg_cpu_time DESC;

