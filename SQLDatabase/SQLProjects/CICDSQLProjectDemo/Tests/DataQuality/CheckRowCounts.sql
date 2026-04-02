
/*
.SYNOPSIS
    Detects significant row count drops in dbo.FactTable between daily loads.

.DESCRIPTION
    Compares today's and yesterday's LoadDate row counts. Throws error 50003
    if today's count is less than 90% of yesterday's count.
*/

DECLARE @YesterdayCount INT;
DECLARE @TodayCount INT;

SELECT @YesterdayCount = COUNT(*)
FROM dbo.FactTable
WHERE LoadDate = DATEADD(day, -1, CAST(GETDATE() AS date));

SELECT @TodayCount = COUNT(*)
FROM dbo.FactTable
WHERE LoadDate = CAST(GETDATE() AS date);

IF @TodayCount < @YesterdayCount * 0.9
    THROW 50003, 'Significant row count drop detected', 1;
