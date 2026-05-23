// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

using System.Net.WebSockets;

namespace CloudSmith.Api.Relay;

/// <summary>
/// Singleton registry that tracks every Relay WebSocket connection that is
/// currently open. Keys on the relay_id (GUID string). Used by the
/// <c>GET /api/v1/relays/{relayId}/connect</c> WebSocket hub to dispatch
/// inbound messages and for server-initiated push (future).
/// </summary>
public interface IConnectedRelayRegistry
{
    /// <summary>Register an accepted WebSocket for <paramref name="relayId"/>.</summary>
    void Register(string relayId, WebSocket socket);

    /// <summary>Remove the registration for <paramref name="relayId"/>.</summary>
    void Unregister(string relayId);

    /// <summary>Look up the active socket for <paramref name="relayId"/>, or null.</summary>
    WebSocket? TryGet(string relayId);

    /// <summary>Snapshot of all currently-connected relay IDs.</summary>
    IReadOnlyCollection<string> ConnectedRelayIds { get; }
}
