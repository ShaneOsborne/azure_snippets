# SQLProjects

Example SQL Database Projects demonstrating schema management and CI/CD-oriented test workflows using the SDK-style `.sqlproj` format.

## Snippet Library

- [CICDSQLProjectDemo](CICDSQLProjectDemo/README.md)
  - End-to-end demo SQL project with schema objects and a categorised post-deployment test suite.

## Notes

- Projects target SQL Server 2022 (DSP `Sql160`) and use the `Microsoft.Build.Sql` SDK.
- Test scripts are excluded from the DACPAC build and run separately via the PowerShell test runner.
