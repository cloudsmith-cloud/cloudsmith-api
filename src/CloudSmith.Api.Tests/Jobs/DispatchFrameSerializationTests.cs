// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Text;
using System.Text.Json;
using CloudSmith.Api.Relay;
using CloudSmith.Core.Jobs;
using FluentAssertions;
using Xunit;

namespace CloudSmith.Api.Tests.Jobs;

/// <summary>
/// AB#2961 — the outbound job.dispatch frame must match the canonical wire shape
/// (contract §1.1, AB#4839): $type discriminator + camelCase property names.
/// </summary>
public sealed class DispatchFrameSerializationTests
{
    [Fact]
    public void JobDispatch_serializes_with_type_discriminator_and_camelCase()
    {
        var jobId = Guid.Parse("d3b07384-d9a0-4c9e-8f6e-1a2b3c4d5e6f");
        var frame = new JobDispatch(
            JobId: jobId,
            JobType: "cluster.validate-network",
            PayloadJson: """{"scriptName":"Validate-Network.ps1"}""",
            IdempotencyKey: "op-key-1",
            Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");

        var bytes = RelayDispatchService.SerializeFrame(frame);
        using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(bytes));
        var root = doc.RootElement;

        root.GetProperty("$type").GetString().Should().Be("job.dispatch");
        root.GetProperty("jobId").GetGuid().Should().Be(jobId);
        root.GetProperty("jobType").GetString().Should().Be("cluster.validate-network");
        root.GetProperty("payloadJson").GetString().Should().Be("""{"scriptName":"Validate-Network.ps1"}""");
        root.GetProperty("idempotencyKey").GetString().Should().Be("op-key-1");
        root.GetProperty("traceparent").GetString().Should().Be("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
    }
}
