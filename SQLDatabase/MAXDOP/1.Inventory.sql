/*
.SYNOPSIS
    Inventories SQL Server instance settings and topology relevant to MAXDOP tuning.

.DESCRIPTION
    Returns:
    - Server and build metadata
    - Current `max degree of parallelism` and `cost threshold for parallelism` values
    - CPU, scheduler, and NUMA-node details from DMVs

.USAGE
    Run in `master` on the target SQL Server instance.

.NOTES
    Requires permission to query system DMVs.
*/

SET NOCOUNT ON;

SELECT 
    SERVERPROPERTY('MachineName') AS MachineName,
    SERVERPROPERTY('InstanceName') AS InstanceName,
    SERVERPROPERTY('ProductVersion') AS ProductVersion,
    SERVERPROPERTY('ProductLevel') AS ProductLevel,
    (SELECT value_in_use FROM sys.configurations WHERE name = 'max degree of parallelism') AS current_maxdop,
    (SELECT value_in_use FROM sys.configurations WHERE name = 'cost threshold for parallelism') AS current_cost_threshold;

-- OS/CPU info
SELECT cpu_count, hyperthread_ratio, physical_memory_kb
FROM sys.dm_os_sys_info;

-- NUMA nodes and schedulers
SELECT node_id, online_scheduler_count, memory_node_id
FROM sys.dm_os_nodes
ORDER BY node_id;

SELECT n.node_id, COUNT(s.scheduler_id) AS logical_processors
FROM sys.dm_os_schedulers s
JOIN sys.dm_os_nodes n ON s.node_id = n.node_id
WHERE s.status = 'VISIBLE ONLINE'
GROUP BY n.node_id
ORDER BY n.node_id;

-- Visible schedulers detail
SELECT scheduler_id, cpu_id, is_online, is_idle, current_tasks_count, runnable_tasks_count
FROM sys.dm_os_schedulers
WHERE status = 'VISIBLE ONLINE'
ORDER BY scheduler_id;

