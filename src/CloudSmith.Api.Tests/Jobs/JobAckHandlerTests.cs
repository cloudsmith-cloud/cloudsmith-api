// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Services.Jobs;
using CloudSmith.Core.Jobs;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CloudSmith.Api.Tests.Jobs;

/// <summary>
/// AB#4844 — job.ack persistence handler: accepted confirms/completes the
/// dispatched transition, duplicate leaves state alone, rejected fails the job
/// immediately with the relay detail (contract §1.2 + failure policy).
/// </summary>
public sealed class JobAckHandlerTests
{
    private static readonly Guid RelayId = Guid.NewGuid();

    private static RelayJobFrameHandler Handler(FakeJobService jobs, FakeJobDirectory? directory = null) =>
        new(jobs, directory ?? new FakeJobDirectory(), new FakeJobAuditWriter(), NullLogger<RelayJobFrameHandler>.Instance);

    [Fact]
    public async Task Accepted_ack_attempts_defensive_queued_to_dispatched()
    {
        var jobId = Guid.NewGuid();
        var jobs  = new FakeJobService { TransitionResult = (_, _, _) => false }; // already dispatched on send

        await Handler(jobs).HandleAckAsync(new JobAck(jobId, JobAckStatus.Accepted), RelayId, CancellationToken.None);

        jobs.Transitions.Should().ContainSingle()
            .Which.Should().Be((jobId, JobStatuses.Queued, JobStatuses.Dispatched));
        jobs.StatusUpdates.Should().BeEmpty();
    }

    [Fact]
    public async Task Duplicate_ack_leaves_state_alone()
    {
        var jobs = new FakeJobService();

        await Handler(jobs).HandleAckAsync(
            new JobAck(Guid.NewGuid(), JobAckStatus.Duplicate), RelayId, CancellationToken.None);

        jobs.Transitions.Should().BeEmpty();
        jobs.StatusUpdates.Should().BeEmpty();
    }

    [Fact]
    public async Task Rejected_ack_fails_dispatched_job_with_detail()
    {
        var jobId = Guid.NewGuid();
        var orgId = Guid.NewGuid();
        var jobs  = new FakeJobService
        {
            TransitionResult = (_, from, _) => from == JobStatuses.Dispatched,
        };
        var directory = new FakeJobDirectory();
        directory.OrgByJob[jobId] = orgId;

        await Handler(jobs, directory).HandleAckAsync(
            new JobAck(jobId, JobAckStatus.Rejected, "unknown target agent"), RelayId, CancellationToken.None);

        jobs.Transitions.Should().Contain((jobId, JobStatuses.Dispatched, JobStatuses.Failed));
        jobs.StatusUpdates.Should().ContainSingle();
        jobs.StatusUpdates[0].OrgId.Should().Be(orgId);
        jobs.StatusUpdates[0].ErrorCode.Should().Be("dispatch-rejected");
        jobs.StatusUpdates[0].ErrorMessage.Should().Be("unknown target agent");
    }

    [Fact]
    public async Task Rejected_ack_falls_back_to_failing_queued_job()
    {
        var jobId = Guid.NewGuid();
        var jobs  = new FakeJobService
        {
            TransitionResult = (_, from, _) => from == JobStatuses.Queued,
        };
        var directory = new FakeJobDirectory();
        directory.OrgByJob[jobId] = Guid.NewGuid();

        await Handler(jobs, directory).HandleAckAsync(
            new JobAck(jobId, JobAckStatus.Rejected), RelayId, CancellationToken.None);

        jobs.Transitions.Should().Contain((jobId, JobStatuses.Queued, JobStatuses.Failed));
        jobs.StatusUpdates.Should().ContainSingle();
    }

    [Fact]
    public async Task Rejected_ack_for_terminal_job_is_a_noop()
    {
        var jobs = new FakeJobService { TransitionResult = (_, _, _) => false };

        await Handler(jobs).HandleAckAsync(
            new JobAck(Guid.NewGuid(), JobAckStatus.Rejected, "late"), RelayId, CancellationToken.None);

        jobs.StatusUpdates.Should().BeEmpty("terminal states are final — no error overwrite");
    }
}
