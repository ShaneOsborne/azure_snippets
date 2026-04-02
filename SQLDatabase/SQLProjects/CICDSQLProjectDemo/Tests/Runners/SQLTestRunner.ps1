<#
.SYNOPSIS
    Discovers and executes all SQL test scripts under the Tests directory.

.DESCRIPTION
    Recursively finds every .sql file under Tests/ and runs each one against
    the target database via Invoke-Sqlcmd. Any THROW in a test script
    terminates execution immediately and surfaces the error.

.NOTES
    - Requires the TEST_DB_CONNECTION environment variable to be set.
    - Requires Invoke-Sqlcmd (SqlServer module or SSMS Tools).
    - Run from SQLDatabase/SQLProjects/CICDSQLProjectDemo/Tests/Runners.

.EXAMPLE
    $env:TEST_DB_CONNECTION = "Server=.;Database=CICDSQLProjectDemo;Integrated Security=True"
    .\SQLTestRunner.ps1
#>

$tests = Get-ChildItem "../../Tests" -Filter *.sql -Recurse

foreach ($test in $tests) {
    Write-Host "Running test $($test.Name)"
    Invoke-Sqlcmd `
        -ConnectionString $env:TEST_DB_CONNECTION `
        -InputFile $test.FullName `
        -ErrorAction Stop
}
