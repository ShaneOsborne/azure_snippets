/*
.SYNOPSIS
    Runs repeatable per-query tests across multiple MAXDOP values and summarizes duration results.

.DESCRIPTION
    Executes the supplied query text repeatedly for each configured MAXDOP value, captures elapsed
    time per run, and outputs aggregate statistics (avg/min/max) by MAXDOP.

.USAGE
    1. Replace `@sql` with the exact target query text.
    2. Adjust `@iterations` and MAXDOP values if needed.
    3. Execute in the database where the query normally runs.

.NOTES
    Run in representative load windows and repeat tests to reduce variance.
*/

DECLARE @sql NVARCHAR(MAX) = N'-- PUT QUERY HERE (no trailing semicolon)';
DECLARE @iterations INT = 3; -- number of repeats per MAXDOP value

IF OBJECT_ID('tempdb..#maxdop_results') IS NOT NULL DROP TABLE #maxdop_results;
CREATE TABLE #maxdop_results (
    tested_at DATETIME2 DEFAULT SYSUTCDATETIME(),
    maxdop INT,
    run_no INT,
    duration_ms BIGINT,
    cpu_time_ms BIGINT NULL
);

DECLARE @maxdop INT;
DECLARE @run INT;
DECLARE @start DATETIME2;
DECLARE @finish DATETIME2;
DECLARE @duration BIGINT;

DECLARE maxdop_cursor CURSOR FOR SELECT v FROM (VALUES (1),(2),(4),(8)) AS t(v);
OPEN maxdop_cursor;
FETCH NEXT FROM maxdop_cursor INTO @maxdop;
WHILE @@FETCH_STATUS = 0
BEGIN
    SET @run = 1;
    WHILE @run <= @iterations
    BEGIN
        SET @start = SYSUTCDATETIME();

        -- Execute the query with MAXDOP hint
        EXEC sp_executesql N'SET STATISTICS XML OFF; ' + @sql + N' OPTION (MAXDOP ' + CAST(@maxdop AS NVARCHAR(3)) + N')';

        SET @finish = SYSUTCDATETIME();
        SET @duration = DATEDIFF(ms, @start, @finish);

        INSERT INTO #maxdop_results (maxdop, run_no, duration_ms)
        VALUES (@maxdop, @run, @duration);

        SET @run = @run + 1;
    END

    FETCH NEXT FROM maxdop_cursor INTO @maxdop;
END

CLOSE maxdop_cursor;
DEALLOCATE maxdop_cursor;

-- Summary results
SELECT maxdop, COUNT(*) AS runs, AVG(duration_ms) AS avg_ms, MIN(duration_ms) AS min_ms, MAX(duration_ms) AS max_ms
FROM #maxdop_results
GROUP BY maxdop
ORDER BY avg_ms;

-- Persist results if needed
SELECT * INTO dbo.MaxDopTestResults_Archive FROM #maxdop_results; -- optional: create in current DB
DROP TABLE #maxdop_results;
