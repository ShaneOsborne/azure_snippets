/*
.SYNOPSIS
    Checks for orphaned rows where foreign key references are unresolved.

.DESCRIPTION
    Left-joins dbo.tableOne to dbo.tableTwo on tableId. Throws error 50005
    if any rows in tableOne have no matching row in tableTwo.
*/

IF EXISTS (
    SELECT 1
    FROM dbo.tableOne f
    LEFT JOIN dbo.tableTwo d
        ON f.tableId = d.tableID
    WHERE d.tableId IS NULL
)
    THROW 50005, 'Orphaned customer references found', 1;