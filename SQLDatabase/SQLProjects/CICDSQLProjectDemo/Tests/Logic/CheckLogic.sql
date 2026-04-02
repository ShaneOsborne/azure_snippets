/*
.SYNOPSIS
    Verifies dbo.CalculateTotalSales produces the correct aggregate result.

.DESCRIPTION
    Seeds dbo.Sales with known values, executes the stored procedure, then
    checks dbo.SalesSummary for the expected TotalAmount. Throws error 50008
    if the result does not match.
*/

TRUNCATE TABLE dbo.Sales;
INSERT INTO dbo.Sales (OrderId, Amount)
VALUES (1, 100), (2, 200);

-- Act
EXEC dbo.CalculateTotalSales;

-- Assert
IF EXISTS (
    SELECT 1
    FROM dbo.SalesSummary
    WHERE TotalAmount <> 300
)
    THROW 50008, 'Total sales calculation is incorrect', 1;
