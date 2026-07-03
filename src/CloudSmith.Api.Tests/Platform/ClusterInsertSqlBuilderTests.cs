// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Endpoints;
using FluentAssertions;
using Xunit;

namespace CloudSmith.Api.Tests.Platform;

public sealed class ClusterInsertSqlBuilderTests
{
    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public void Build_EmitsSqlMatchingAvailableColumns(bool hasClusterType, bool hasRelayId)
    {
        var shape = ClusterInsertSqlBuilder.Build(hasClusterType, hasRelayId);

        shape.UsesClusterType.Should().Be(hasClusterType);
        shape.UsesRelayId.Should().Be(hasRelayId);

        shape.Sql.Should().Contain("INSERT INTO cluster_mgmt.clusters");
        shape.Sql.Should().Contain("org_id").And.Contain("site_id").And.Contain("name").And.Contain("status");
        shape.Sql.Should().Contain("@org_id").And.Contain("@site_id").And.Contain("@name").And.Contain("'unknown'");

        if (hasClusterType)
            shape.Sql.Should().Contain("cluster_type").And.Contain("@cluster_type");
        else
            shape.Sql.Should().NotContain("cluster_type").And.NotContain("@cluster_type");

        if (hasRelayId)
            shape.Sql.Should().Contain("relay_id").And.Contain("@relay_id");
        else
            shape.Sql.Should().NotContain("relay_id").And.NotContain("@relay_id");
    }
}
