// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Services.Jobs;
using CloudSmith.Core.Jobs;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CloudSmith.Api.Tests.Jobs;

/// <summary>
/// AB#4841 — job.result frame handler: first result wins (persist + audit),
/// duplicates and late results for terminal jobs are no-ops with no audit row.
/// </summary>
public sealed class JobResultHandlerTests
{
    private static readonly Guid RelayId = Guid.NewGuid();

    private static JobResult Result(Guid jobId, bool succeeded = true) => new(
        JobId:       jobId,
        Succeeded:   succeeded,
        ExitCode:    succeeded ? 0 : 1,
        Output:      "done",
        Error:       succeeded ? null : "boom",
        CompletedAt: DateTimeOffset.UtcNow);

    private static (RelayJobFrameHandler Handler, FakeJobService Jobs, FakeJobDirectory Directory, FakeJobAuditWriter Audit)
        Build()
    {
        var jobs      = new FakeJobService();
        var directory = new FakeJobDirectory();
        var audit     = new FakeJobAuditWriter();
        var handler   = new RelayJobFrameHandler(jobs, directory, audit, NullLogger<RelayJobFrameHandler>.Instance);
        return (handler, jobs, directory, audit);
    }

    [Fact]
    public async Task First_result_is_recorded_and_audited()
    {
        var jobId = Guid.NewGuid();
        var orgId = Guid.NewGuid();
        var (handler, jobs, directory, audit) = Build();
        directory.OrgByJob[jobId] = orgId;

        var result = Result(jobId);
        await handler.HandleResultAsync(result, RelayId, CancellationToken.None);

        jobs.RecordedResults.Should().ContainSingle();
        jobs.RecordedResults[0].JobId.Should().Be(jobId);
        jobs.RecordedResults[0].Result.Should().Be(result);

        audit.Writes.Should().ContainSingle();
        audit.Writes[0].OrgId.Should().Be(orgId);
        audit.Writes[0].JobId.Should().Be(jobId);
        audit.Writes[0].RelayId.Should().Be(RelayId);
    }

    [Fact]
    public async Task Duplicate_result_is_a_noop_with_no_audit()
    {
        var jobId = Guid.NewGuid();
        var (handler, jobs, directory, audit) = Build();
        directory.OrgByJob[jobId] = Guid.NewGuid();
        jobs.RecordResultResult = (_, _) => false; // job already terminal / result already applied

        await handler.HandleResultAsync(Result(jobId), RelayId, CancellationToken.None);

        jobs.RecordedResults.Should().ContainSingle("the idempotent record attempt still happens");
        audit.Writes.Should().BeEmpty("duplicates must not produce a second audit row");
    }

    [Fact]
    public async Task Failed_result_is_recorded_and_audited()
    {
        var jobId = Guid.NewGuid();
        var (handler, jobs, directory, audit) = Build();
        directory.OrgByJob[jobId] = Guid.NewGuid();

        await handler.HandleResultAsync(Result(jobId, succeeded: false), RelayId, CancellationToken.None);

        jobs.RecordedResults.Should().ContainSingle();
        audit.Writes.Should().ContainSingle();
        audit.Writes[0].Result.Succeeded.Should().BeFalse();
    }

    [Fact]
    public async Task Missing_org_row_skips_audit_without_throwing()
    {
        var (handler, jobs, _, audit) = Build();

        var act = async () => await handler.HandleResultAsync(Result(Guid.NewGuid()), RelayId, CancellationToken.None);

        await act.Should().NotThrowAsync();
        audit.Writes.Should().BeEmpty();
    }
}
