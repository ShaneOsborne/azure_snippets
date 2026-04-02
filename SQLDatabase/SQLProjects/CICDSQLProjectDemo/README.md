# CICDSQLProjectDemo

A minimal SDK-style SQL Database Project (`Microsoft.Build.Sql`) demonstrating how to structure schema objects and a categorised post-deployment test suite for CI/CD pipelines.

## Project Structure

```
CICDSQLProjectDemo/
├── CICDSQLProjectDemo.sqlproj   # SDK-style project file
├── dbo/
│   ├── Tables/
│   │   └── DemoTable.sql        # Core demo table
│   └── Views/
│       └── vwDemoTable.sql      # Filtered view over DemoTable
└── Tests/
    ├── DataQuality/             # Row-level data validation tests
    ├── Logic/                   # Business logic correctness tests
    ├── Misc/                    # Post-deploy state checks
    ├── Performance/             # Query Store regression checks
    ├── Schema/                  # Schema existence/structure checks
    └── Runners/
        └── SQLTestRunner.ps1    # PowerShell test runner
```

## Schema Objects

- `dbo.DemoTable`
  - Simple identity-keyed table with a `Forename` column.

- `dbo.vwDemoTable`
  - View over `DemoTable` filtered to rows where `Forename` ends with `ane`.

## Test Categories

| Folder         | File                               | What it checks |
|----------------|------------------------------------|----------------|
| `Schema`       | `ColumnCheck.sql`                  | `Forename` column exists on `DemoTable` |
| `DataQuality`  | `CheckDataQuality.sql`             | `Forename` length is between 2 and 20 characters |
| `DataQuality`  | `CheckOrphanedData.sql`            | No orphaned FK references between `tableOne` and `tableTwo` |
| `DataQuality`  | `CheckRowCounts.sql`               | Today's `FactTable` load is not more than 10% below yesterday's |
| `Logic`        | `CheckLogic.sql`                   | `dbo.CalculateTotalSales` produces the expected total |
| `Performance`  | `CheckQueryStrorePerformance.sql`  | No `DemoTable` queries have regressed in average duration |
| `Misc`         | `CheckDeploymentState.sql`         | No invalid (non-MS-shipped) objects exist post-deploy |

Each test uses `THROW` with a unique error number to fail the runner on detection.

## Prerequisites

- PowerShell 5.1+ or PowerShell 7+
- `SqlServer` or `Az.Sql` PowerShell module providing `Invoke-Sqlcmd`
- `TEST_DB_CONNECTION` environment variable set to a valid SQL Server connection string
- Target database deployed (DACPAC published) before running tests

Install `Invoke-Sqlcmd` if needed:

```powershell
Install-Module SqlServer -Scope CurrentUser
```

## Usage

### 1) Build the DACPAC

```powershell
cd SQLDatabase/SQLProjects/CICDSQLProjectDemo
dotnet build
```

### 2) Deploy to target database

```powershell
SqlPackage /Action:Publish /SourceFile:bin\Debug\CICDSQLProjectDemo.dacpac /TargetConnectionString:"$env:TEST_DB_CONNECTION"
```

### 3) Run post-deployment tests

```powershell
cd SQLDatabase/SQLProjects/CICDSQLProjectDemo/Tests/Runners
$env:TEST_DB_CONNECTION = "Server=.;Database=CICDSQLProjectDemo;Integrated Security=True"
./SQLTestRunner.ps1
```

The runner discovers all `.sql` files under `Tests/` recursively and executes them in order. Any `THROW` in a test script causes the runner to stop and surface the error.

## Notes

- Test scripts are excluded from the DACPAC build via the `.sqlproj` `<Build Remove="Tests\**\*.sql" />` pattern; they are source-controlled but not deployed as schema objects.
- Adapt table/column/procedure references in the test scripts to match your actual schema before use.
- Tests are intended to run against a deployed database in a CI/CD pipeline (e.g. Azure DevOps, GitHub Actions) after each deploy step.
