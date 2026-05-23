// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Concurrent;
using System.Net.WebSockets;

namespace CloudSmith.Api.Relay;

/// <inheritdoc cref="IConnectedRelayRegistry"/>
public sealed class ConnectedRelayRegistry : IConnectedRelayRegistry
{
    private readonly ConcurrentDictionary<string, WebSocket> _sockets =
        new(StringComparer.OrdinalIgnoreCase);

    public void Register(string relayId, WebSocket socket)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relayId);
        ArgumentNullException.ThrowIfNull(socket);
        _sockets[relayId] = socket;
    }

    public void Unregister(string relayId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relayId);
        _sockets.TryRemove(relayId, out _);
    }

    public WebSocket? TryGet(string relayId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relayId);
        return _sockets.TryGetValue(relayId, out var ws) ? ws : null;
    }

    public IReadOnlyCollection<string> ConnectedRelayIds =>
        (IReadOnlyCollection<string>)_sockets.Keys;
}
