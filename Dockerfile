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
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://localhost:8080/health/live || exit 1
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "CloudSmith.Api.dll"]
