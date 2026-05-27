FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY nuget.config .
COPY src/CloudSmith.Api/CloudSmith.Api.csproj src/CloudSmith.Api/
COPY src/CloudSmith.Api.Tests/CloudSmith.Api.Tests.csproj src/CloudSmith.Api.Tests/
RUN --mount=type=secret,id=nuget_token \
    TOKEN=$(cat /run/secrets/nuget_token) && \
    dotnet nuget update source cloudsmith-github --username x-access-token --password "$TOKEN" --store-password-in-clear-text --configfile nuget.config && \
    dotnet restore src/CloudSmith.Api/CloudSmith.Api.csproj
COPY . .
RUN dotnet publish src/CloudSmith.Api/CloudSmith.Api.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app
# Install curl for healthcheck — dotnet/aspnet:9.0 (Debian Bookworm) does not include it
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD curl -sf http://localhost:8080/health/live || exit 1
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "CloudSmith.Api.dll"]
