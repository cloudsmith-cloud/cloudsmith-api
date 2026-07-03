// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Relay;
using CloudSmith.Api.Services.Jobs;
using CloudSmith.Core.Jobs;

namespace CloudSmith.Api.Tests.Jobs;

/// <summary>Hand-rolled IJobService fake — records calls, configurable outcomes.</summary>
public sealed class FakeJobService : IJobService
{
    public List<(Guid JobId, string From, string To)> Transitions { get; } = [];
    public Func<Guid, string, string, bool> TransitionResult { get; set; } =
        (_, from, to) => JobStateMachine.CanTransition(from, to);

    public List<(Guid JobId, Guid OrgId, string Status, string? ErrorCode, string? ErrorMessage)> StatusUpdates { get; } = [];

    public List<(Guid JobId, JobResult Result)> RecordedResults { get; } = [];
    public Func<Guid, JobResult, bool> RecordResultResult { get; set; } = (_, _) => true;

    public Task<bool> TryTransitionAsync(Guid jobId, string from, string to, CancellationToken ct = default)
    {
        Transitions.Add((jobId, from, to));
        return Task.FromResult(TransitionResult(jobId, from, to));
    }

    public Task UpdateJobStatusAsync(Guid jobId, Guid orgId, string status,
        string? resultJson = null, string? errorCode = null, string? errorMessage = null,
        CancellationToken ct = default)
    {
        StatusUpdates.Add((jobId, orgId, status, errorCode, errorMessage));
        return Task.CompletedTask;
    }

    public Task<bool> RecordResultAsync(Guid jobId, JobResult result, CancellationToken ct = default)
    {
        RecordedResults.Add((jobId, result));
        return Task.FromResult(RecordResultResult(jobId, result));
    }

    public Task<JobRecord> CreateJobAsync(Guid orgId, CreateJobRequest request, CancellationToken ct = default)
        => throw new NotSupportedException();

    public Task<JobRecord?> GetJobAsync(Guid jobId, Guid orgId, CancellationToken ct = default)
        => Task.FromResult<JobRecord?>(null);

    public Task<(IReadOnlyList<JobLogEntry> Items, int TotalItems)> GetJobLogAsync(
        Guid jobId, Guid orgId, string? severity, int page, int pageSize, CancellationToken ct = default)
        => throw new NotSupportedException();

    public Task AppendLogAsync(Guid jobId, Guid orgId, string severity, string message, string? source, CancellationToken ct = default)
        => Task.CompletedTask;
}

/// <summary>Hand-rolled IRelayDispatchService fake — records frames, configurable outcome.</summary>
public sealed class FakeRelayDispatchService : IRelayDispatchService
{
    public List<(Guid OrgId, Guid? SiteId, string Env, JobDispatch Frame)> Dispatches { get; } = [];
    public DispatchResult Result { get; set; } = new(DispatchStatus.Dispatched, Guid.NewGuid());

    public Task<DispatchResult> TryDispatchAsync(
        Guid orgId, Guid? siteId, string env, JobDispatch frame, CancellationToken ct = default)
    {
        Dispatches.Add((orgId, siteId, env, frame));
        return Task.FromResult(Result);
    }
}

/// <summary>Hand-rolled IJobDirectory fake.</summary>
public sealed class FakeJobDirectory : IJobDirectory
{
    public Dictionary<Guid, Guid> OrgByJob { get; } = [];

    public Task<Guid?> GetOrgIdAsync(Guid jobId, CancellationToken ct = default)
        => Task.FromResult(OrgByJob.TryGetValue(jobId, out var orgId) ? (Guid?)orgId : null);
}

/// <summary>Hand-rolled IJobAuditWriter fake — records job.completed audit writes.</summary>
public sealed class FakeJobAuditWriter : IJobAuditWriter
{
    public List<(Guid OrgId, Guid JobId, Guid RelayId, JobResult Result)> Writes { get; } = [];

    public Task WriteJobCompletedAsync(Guid orgId, Guid jobId, Guid relayId, JobResult result, CancellationToken ct = default)
    {
        Writes.Add((orgId, jobId, relayId, result));
        return Task.CompletedTask;
    }
}
