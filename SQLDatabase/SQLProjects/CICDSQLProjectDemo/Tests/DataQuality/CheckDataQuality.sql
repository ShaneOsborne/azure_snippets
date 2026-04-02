
/*
.SYNOPSIS
    Validates Forename values in dbo.DemoTable are within acceptable length bounds.

.DESCRIPTION
    Checks that no Forename is shorter than 2 or longer than 20 characters.
    Throws error 50004 if out-of-bounds values are found.
*/

IF EXISTS (
    SELECT 1
    FROM dbo.DemoTable
    WHERE LENGTH(Forename) < 2
       OR LENGTH(Forename) > 20
)
    THROW 50004, 'DemoTable:Forename out of bounds', 1;
