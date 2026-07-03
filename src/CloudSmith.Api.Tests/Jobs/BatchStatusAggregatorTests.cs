// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Services.Jobs;
using CloudSmith.Core.Jobs;
using FluentAssertions;
using Xunit;

namespace CloudSmith.Api.Tests.Jobs;

/// <summary>
/// AB#4843 — batch status is a pure function of child job states
/// (design/api-surface/job-batch-endpoints.md, "Status aggregation semantics").
/// </summary>
public sealed class BatchStatusAggregatorTests
{
    private static BatchChildCounts Counts(
        int queued = 0, int dispatched = 0, int running = 0,
        int succeeded = 0, int failed = 0, int timedOut = 0, int cancelled = 0) =>
        new(queued, dispatched, running, succeeded, failed, timedOut, cancelled);

    [Fact]
    public void All_queued_is_queued() =>
        BatchStatusAggregator.Compute(Counts(queued: 5)).Should().Be(BatchStatuses.Queued);

    [Fact]
    public void Empty_batch_is_queued() =>
        BatchStatusAggregator.Compute(Counts()).Should().Be(BatchStatuses.Queued);

    [Theory]
    [InlineData(2, 1, 0, 0)] // queued + dispatched
    [InlineData(0, 0, 3, 0)] // all running
    [InlineData(1, 0, 1, 2)] // non-terminal mixed with terminal children
    public void Any_nonterminal_and_not_all_queued_is_running(int queued, int dispatched, int running, int succeeded) =>
        BatchStatusAggregator.Compute(Counts(queued, dispatched, running, succeeded))
            .Should().Be(BatchStatuses.Running);

    [Fact]
    public void All_succeeded_is_succeeded() =>
        BatchStatusAggregator.Compute(Counts(succeeded: 4)).Should().Be(BatchStatuses.Succeeded);

    [Fact]
    public void All_terminal_mixed_success_is_partial() =>
        BatchStatusAggregator.Compute(Counts(succeeded: 3, failed: 1)).Should().Be(BatchStatuses.Partial);

    [Fact]
    public void Timed_out_counts_as_unsuccessful_for_partial() =>
        BatchStatusAggregator.Compute(Counts(succeeded: 2, timedOut: 1)).Should().Be(BatchStatuses.Partial);

    [Fact]
    public void All_terminal_none_succeeded_is_failed() =>
        BatchStatusAggregator.Compute(Counts(failed: 2, timedOut: 1)).Should().Be(BatchStatuses.Failed);

    [Fact]
    public void All_cancelled_is_cancelled() =>
        BatchStatusAggregator.Compute(Counts(cancelled: 3)).Should().Be(BatchStatuses.Cancelled);

    [Fact]
    public void Cancelled_mixed_with_succeeded_is_partial() =>
        BatchStatusAggregator.Compute(Counts(succeeded: 1, cancelled: 2)).Should().Be(BatchStatuses.Partial);

    [Fact]
    public void Cancelled_mixed_with_failed_is_failed() =>
        BatchStatusAggregator.Compute(Counts(failed: 1, cancelled: 2)).Should().Be(BatchStatuses.Failed);

    [Fact]
    public void FromStatusCounts_maps_canonical_job_statuses()
    {
        var counts = BatchStatusAggregator.FromStatusCounts(
        [
            (JobStatuses.Queued, 1),
            (JobStatuses.Dispatched, 2),
            (JobStatuses.Running, 3),
            (JobStatuses.Succeeded, 4),
            (JobStatuses.Failed, 5),
            (JobStatuses.TimedOut, 6),
            (JobStatuses.Cancelled, 7),
        ]);

        counts.Should().Be(new BatchChildCounts(1, 2, 3, 4, 5, 6, 7));
        counts.Total.Should().Be(28);
        counts.Terminal.Should().Be(22);
    }

    [Theory]
    [InlineData(BatchStatuses.Succeeded, true)]
    [InlineData(BatchStatuses.Partial, true)]
    [InlineData(BatchStatuses.Failed, true)]
    [InlineData(BatchStatuses.Cancelled, true)]
    [InlineData(BatchStatuses.Queued, false)]
    [InlineData(BatchStatuses.Running, false)]
    public void IsTerminal_matches_design_terminal_set(string status, bool expected) =>
        BatchStatuses.IsTerminal(status).Should().Be(expected);
}
