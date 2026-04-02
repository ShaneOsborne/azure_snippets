/*
.SYNOPSIS
  Verifies expected columns exist on dbo.DemoTable.

.DESCRIPTION
  Checks sys.columns for the presence of the Forename column.
  Throws error 50001 if the column is missing.
*/

--Column existence
IF NOT EXISTS (
    SELECT 1
    FROM sys.columns
    WHERE object_id = OBJECT_ID('dbo.DemoTable')
      AND name = 'Forename'
)
    THROW 50001, 'Forename column missing', 1;