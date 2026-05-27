// Copyright 2026 CloudSmith Contributors
// SPDX-License-Identifier: Apache-2.0

namespace CloudSmith.Api.Services;

/// <summary>
/// Represents a single entry in the published CloudSmith module catalog.
/// Each entry corresponds to a cosign-signed OCI container image on ghcr.io.
/// </summary>
public sealed record ModuleCatalogEntry(
    string Id,
    string Name,
    string Version,
    string Description,
    string Publisher,
    string GhcrImageRef,
    string ManifestUrl,
    string? SignatureRef,
    bool IsVerified);

/// <summary>
/// Provides access to the CloudSmith published module catalog.
/// The default implementation reads from the GitHub Packages OCI registry
/// (ghcr.io/cloudsmith-cloud) with a 5-minute in-memory cache.
/// AB#1925.
/// </summary>
public interface IModuleCatalogService
{
    /// <summary>
    /// Returns all modules currently available in the catalog.
    /// Results are filtered to packages that carry the
    /// <c>org.cloudsmith.module=true</c> OCI label.
    /// </summary>
    Task<IReadOnlyList<ModuleCatalogEntry>> ListAsync(CancellationToken ct = default);

    /// <summary>
    /// Returns metadata for a specific module, optionally pinned to a version.
    /// Returns <see langword="null"/> when not found.
    /// </summary>
    Task<ModuleCatalogEntry?> GetAsync(string id, string? version = null, CancellationToken ct = default);
}
