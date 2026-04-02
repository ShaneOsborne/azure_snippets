# SQLDatabase

Collection of SQL Server and Azure SQL oriented snippets for inventory, performance diagnostics, and tuning workflows.

## Snippet Library

- [MAXDOP](MAXDOP/README.md)
  - Scripts for baseline collection and per-query MAXDOP testing.
- [SQLProjects](SQLProjects/README.md)
  - Example SQL Database Project with CI/CD-oriented post-deployment test scripts.

## Notes

- Run scripts first in non-production or controlled maintenance windows where possible.
- Validate recommendations against workload patterns before applying persistent configuration changes.