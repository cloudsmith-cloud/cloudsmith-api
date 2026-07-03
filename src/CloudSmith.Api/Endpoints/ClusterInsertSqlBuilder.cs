// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

namespace CloudSmith.Api.Endpoints;

/// <summary>
/// Builds a column-aware INSERT shape for cluster registration so fresh databases
/// missing extension columns (cluster_type/relay_id) do not fail with SQL 42703.
/// </summary>
public static class ClusterInsertSqlBuilder
{
    public static ClusterInsertShape Build(bool hasClusterType, bool hasRelayId)
    {
        var columns = new List<string> { "org_id", "site_id", "name" };
        var values = new List<string> { "@org_id", "@site_id", "@name" };

        if (hasClusterType)
        {
            columns.Add("cluster_type");
            values.Add("@cluster_type");
        }

        if (hasRelayId)
        {
            columns.Add("relay_id");
            values.Add("@relay_id");
        }

        columns.Add("status");
        values.Add("'unknown'");

        var sql = $"""
            INSERT INTO cluster_mgmt.clusters
                ({string.Join(", ", columns)})
            VALUES
                ({string.Join(", ", values)})
            RETURNING cluster_id
            """;

        return new ClusterInsertShape(sql, hasClusterType, hasRelayId);
    }
}

public sealed record ClusterInsertShape(string Sql, bool UsesClusterType, bool UsesRelayId);
