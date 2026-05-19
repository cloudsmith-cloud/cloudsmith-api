// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace CloudSmith.Api.Tests.Health;

[Trait("Category", "Integration")]
public sealed class HealthEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public HealthEndpointTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task HealthLive_ReturnsOk()
    {
        var response = await _client.GetAsync("/health/live");
        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("healthy", body);
    }
}
