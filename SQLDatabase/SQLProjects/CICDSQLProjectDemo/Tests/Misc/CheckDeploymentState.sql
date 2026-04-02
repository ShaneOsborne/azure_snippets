/*
.SYNOPSIS
  Checks for invalid user-defined objects following a deployment.

.DESCRIPTION
  Queries sys.objects for non-MS-shipped objects that are marked invalid.
  Throws error 50007 if any are found, indicating a broken schema after deploy.
*/

-- Check invalid objects
IF EXISTS (
    SELECT 1
    FROM sys.objects
    WHERE is_ms_shipped = 0
      AND OBJECTPROPERTY(object_id, 'IsSchemaBound') = 0
      AND OBJECTPROPERTY(object_id, 'IsValid') = 0
)
    THROW 50007, 'Invalid SQL objects detected post-deploy', 1
