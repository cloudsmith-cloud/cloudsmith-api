// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Relay;
using CloudSmith.Api.Services.Jobs;
using CloudSmith.Core.Jobs;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CloudSmith.Api.Tests.Jobs;

/// <summary>
/// AB#4844 — dispatcher claim/transition logic: send → queued→dispatched transition,
/// no-connected-relay leaves the job queued, and timeout sweep adjudication.
/// </summary>
public sealed class JobDispatchLogicTests
{
    private static QueuedJobClaim Claim(Guid? siteId = null) => new(
        JobId:          Guid.NewGuid(),
        OrgId:          Guid.NewGuid(),
        JobType:        "cluster.validate-network",
        PayloadJson:    """{"clusterName":"clu-01"}""",
        IdempotencyKey: "idem-1",
        SiteId:         siteId ?? Guid.NewGuid(),
        Env:            "default");

    [Fact]
    public async Task Successful_send_transitions_queued_to_dispatched()
    {
        var claim    = Claim();
        var dispatch = new FakeRelayDispatchService { Result = new(DispatchStatus.Dispatched, Guid.NewGuid()) };
        var jobs     = new FakeJobService();

        var status = await JobDispatchLogic.DispatchOneAsync(claim, dispatch, jobs, NullLogger.Instance, CancellationToken.None);

        status.Should().Be(DispatchStatus.Dispatched);
        dispatch.Dispatches.Should().ContainSingle();
        var (orgId, siteId, env, frame) = dispatch.Dispatches[0];
        orgId.Should().Be(claim.OrgId);
        siteId.Should().Be(claim.SiteId);
        env.Should().Be("default");
        frame.JobId.Should().Be(claim.JobId);
        frame.JobType.Should().Be(claim.JobType);
        frame.PayloadJson.Should().Be(claim.PayloadJson);
        frame.IdempotencyKey.Should().Be("idem-1");

        jobs.Transitions.Should().ContainSingle()
            .Which.Should().Be((claim.JobId, JobStatuses.Queued, JobStatuses.Dispatched));
    }

    [Fact]
    public async Task No_connected_relay_leaves_job_queued()
    {
        var claim    = Claim();
        var dispatch = new FakeRelayDispatchService { Result = new(DispatchStatus.NoRelayConnected) };
        var jobs     = new FakeJobService();

        var status = await JobDispatchLogic.DispatchOneAsync(claim, dispatch, jobs, NullLogger.Instance, CancellationToken.None);

        status.Should().Be(DispatchStatus.NoRelayConnected);
        jobs.Transitions.Should().BeEmpty("the job must stay queued for the rescan/sweeper");
    }

    [Fact]
    public async Task Send_failure_leaves_job_queued()
    {
        var claim    = Claim();
        var dispatch = new FakeRelayDispatchService { Result = new(DispatchStatus.SendFailed, Guid.NewGuid()) };
        var jobs     = new FakeJobService();

        var status = await JobDispatchLogic.DispatchOneAsync(claim, dispatch, jobs, NullLogger.Instance, CancellationToken.None);

        status.Should().Be(DispatchStatus.SendFailed);
        jobs.Transitions.Should().BeEmpty();
    }

    [Fact]
    public async Task Lost_transition_race_does_not_throw()
    {
        var claim    = Claim();
        var dispatch = new FakeRelayDispatchService { Result = new(DispatchStatus.Dispatched, Guid.NewGuid()) };
        var jobs     = new FakeJobService { TransitionResult = (_, _, _) => false };

        var act = async () => await JobDispatchLogic.DispatchOneAsync(claim, dispatch, jobs, NullLogger.Instance, CancellationToken.None);

        await act.Should().NotThrowAsync("a lost CAS race is benign — relay-side dedupe covers the double-send");
    }
}

/// <summary>
/// AB#4844 — timeout sweeper: queued past deadline fails with no-route;
/// dispatched/running past deadline become timed_out (API-side watchdog owns timeouts).
/// </summary>
public sealed class TimeoutSweeperTests
{
    [Fact]
    public async Task Queued_past_deadline_fails_with_no_route()
    {
        var job    = new ExpiredJob(Guid.NewGuid(), Guid.NewGuid(), JobStatuses.Queued);
        var jobs   = new FakeJobService();
        var rollup = new FakeBatchRollupService();

        await JobDispatchLogic.SweepOneAsync(job, jobs, rollup, NullLogger.Instance, CancellationToken.None);

        jobs.Transitions.Should().ContainSingle()
            .Which.Should().Be((job.JobId, JobStatuses.Queued, JobStatuses.Failed));
        jobs.StatusUpdates.Should().ContainSingle();
        jobs.StatusUpdates[0].ErrorCode.Should().Be("no-route");
        jobs.StatusUpdates[0].OrgId.Should().Be(job.OrgId);
        rollup.RolledUpJobIds.Should().ContainSingle().Which.Should().Be(job.JobId);
    }

    [Theory]
    [InlineData("dispatched")]
    [InlineData("running")]
    public async Task Dispatched_and_running_past_deadline_time_out(string status)
    {
        var job    = new ExpiredJob(Guid.NewGuid(), Guid.NewGuid(), status);
        var jobs   = new FakeJobService();
        var rollup = new FakeBatchRollupService();

        await JobDispatchLogic.SweepOneAsync(job, jobs, rollup, NullLogger.Instance, CancellationToken.None);

        jobs.Transitions.Should().ContainSingle()
            .Which.Should().Be((job.JobId, status, JobStatuses.TimedOut));
        jobs.StatusUpdates.Should().BeEmpty();
        rollup.RolledUpJobIds.Should().ContainSingle("timed_out is terminal and must roll up into any containing batch");
    }

    [Fact]
    public async Task Lost_sweep_race_writes_no_error_fields()
    {
        var job    = new ExpiredJob(Guid.NewGuid(), Guid.NewGuid(), JobStatuses.Queued);
        var jobs   = new FakeJobService { TransitionResult = (_, _, _) => false };
        var rollup = new FakeBatchRollupService();

        await JobDispatchLogic.SweepOneAsync(job, jobs, rollup, NullLogger.Instance, CancellationToken.None);

        jobs.StatusUpdates.Should().BeEmpty("a result arriving mid-sweep must not be clobbered");
        rollup.RolledUpJobIds.Should().BeEmpty();
    }
}
