// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Core.Jobs;

namespace CloudSmith.Api.Services.Jobs;

/// <summary>Counts of a batch's child jobs by canonical status.</summary>
public sealed record BatchChildCounts(
    int Queued,
    int Dispatched,
    int Running,
    int Succeeded,
    int Failed,
    int TimedOut,
    int Cancelled)
{
    public int Total    => Queued + Dispatched + Running + Succeeded + Failed + TimedOut + Cancelled;
    public int Terminal => Succeeded + Failed + TimedOut + Cancelled;
}

/// <summary>Canonical batch status values (design/api-surface/job-batch-endpoints.md).</summary>
public static class BatchStatuses
{
    public const string Queued    = "queued";
    public const string Running   = "running";
    public const string Succeeded = "succeeded";
    public const string Partial   = "partial";
    public const string Failed    = "failed";
    public const string Cancelled = "cancelled";

    public static bool IsTerminal(string status) =>
        status is Succeeded or Partial or Failed or Cancelled;
}

/// <summary>
/// AB#4843 — batch status is a pure function of child job states
/// (design/api-surface/job-batch-endpoints.md, "Status aggregation semantics"):
/// <list type="bullet">
/// <item>queued    — all children queued</item>
/// <item>running   — ≥1 child non-terminal and not all queued</item>
/// <item>succeeded — all children succeeded</item>
/// <item>partial   — all children terminal, mix of succeeded and unsuccessful</item>
/// <item>failed    — all children terminal, none succeeded</item>
/// <item>cancelled — all children cancelled</item>
/// </list>
/// timed_out children count as unsuccessful for partial/failed purposes.
/// </summary>
public static class BatchStatusAggregator
{
    public static string Compute(BatchChildCounts c)
    {
        if (c.Total == 0 || c.Queued == c.Total)
            return BatchStatuses.Queued;

        if (c.Terminal < c.Total)
            return BatchStatuses.Running;

        // All terminal from here down.
        if (c.Succeeded == c.Total)
            return BatchStatuses.Succeeded;

        if (c.Cancelled == c.Total)
            return BatchStatuses.Cancelled;

        return c.Succeeded > 0 ? BatchStatuses.Partial : BatchStatuses.Failed;
    }

    /// <summary>Builds counts from (status, count) rows as returned by the GROUP BY query.</summary>
    public static BatchChildCounts FromStatusCounts(IEnumerable<(string Status, int Count)> rows)
    {
        int queued = 0, dispatched = 0, running = 0, succeeded = 0, failed = 0, timedOut = 0, cancelled = 0;
        foreach (var (status, count) in rows)
        {
            switch (status)
            {
                case JobStatuses.Queued:     queued     += count; break;
                case JobStatuses.Dispatched: dispatched += count; break;
                case JobStatuses.Running:    running    += count; break;
                case JobStatuses.Succeeded:  succeeded  += count; break;
                case JobStatuses.Failed:     failed     += count; break;
                case JobStatuses.TimedOut:   timedOut   += count; break;
                case JobStatuses.Cancelled:  cancelled  += count; break;
            }
        }
        return new BatchChildCounts(queued, dispatched, running, succeeded, failed, timedOut, cancelled);
    }
}
