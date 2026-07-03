// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using CloudSmith.Api.Relay;
using FluentAssertions;
using Xunit;

namespace CloudSmith.Api.Tests.Jobs;

/// <summary>
/// AB#2765 / AB#2961 — strict (site_id, env) routing selection per the frozen
/// contract §5: exact equality on both keys, connected relays only, no cross-site
/// or cross-env fallback, last_seen_at DESC tie-break, null site never routes.
/// </summary>
public sealed class RelayRoutingTests
{
    private static readonly Guid SiteA = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid SiteB = Guid.Parse("22222222-2222-2222-2222-222222222222");

    private static readonly Guid Relay1 = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly Guid Relay2 = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    private static readonly Guid Relay3 = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc");

    private static string[] Connected(params Guid[] ids) => ids.Select(i => i.ToString()).ToArray();

    [Fact]
    public void Selects_relay_matching_site_and_env()
    {
        var candidates = new[]
        {
            new RelayCandidate(Relay1, SiteA, "default", DateTimeOffset.UtcNow),
            new RelayCandidate(Relay2, SiteB, "default", DateTimeOffset.UtcNow),
        };

        var selected = RelayRouting.SelectRelay(SiteA, "default", candidates, Connected(Relay1, Relay2));

        selected.Should().Be(Relay1);
    }

    [Fact]
    public void Never_falls_back_across_env()
    {
        var candidates = new[]
        {
            new RelayCandidate(Relay1, SiteA, "prod", DateTimeOffset.UtcNow),
        };

        var selected = RelayRouting.SelectRelay(SiteA, "default", candidates, Connected(Relay1));

        selected.Should().BeNull("cross-env fallback is forbidden by contract §5");
    }

    [Fact]
    public void Never_falls_back_across_site()
    {
        var candidates = new[]
        {
            new RelayCandidate(Relay1, SiteB, "default", DateTimeOffset.UtcNow),
        };

        var selected = RelayRouting.SelectRelay(SiteA, "default", candidates, Connected(Relay1));

        selected.Should().BeNull("cross-site fallback is forbidden by contract §5");
    }

    [Fact]
    public void Null_job_site_is_never_routable()
    {
        var candidates = new[]
        {
            new RelayCandidate(Relay1, null, "default", DateTimeOffset.UtcNow),
        };

        var selected = RelayRouting.SelectRelay(null, "default", candidates, Connected(Relay1));

        selected.Should().BeNull("a job with site_id IS NULL never routes to a Relay");
    }

    [Fact]
    public void Ignores_matching_but_disconnected_relays()
    {
        var candidates = new[]
        {
            new RelayCandidate(Relay1, SiteA, "default", DateTimeOffset.UtcNow),
        };

        var selected = RelayRouting.SelectRelay(SiteA, "default", candidates, Connected(Relay2));

        selected.Should().BeNull("only relays with an open WebSocket are eligible");
    }

    [Fact]
    public void No_connected_relay_returns_null()
    {
        var selected = RelayRouting.SelectRelay(
            SiteA, "default", Array.Empty<RelayCandidate>(), Array.Empty<string>());

        selected.Should().BeNull();
    }

    [Fact]
    public void Most_recently_seen_wins_tie_break()
    {
        var now = DateTimeOffset.UtcNow;
        var candidates = new[]
        {
            new RelayCandidate(Relay1, SiteA, "default", now.AddMinutes(-10)),
            new RelayCandidate(Relay2, SiteA, "default", now),
            new RelayCandidate(Relay3, SiteA, "default", null),
        };

        var selected = RelayRouting.SelectRelay(SiteA, "default", candidates, Connected(Relay1, Relay2, Relay3));

        selected.Should().Be(Relay2, "most recent last_seen_at wins per contract §5");
    }
}
