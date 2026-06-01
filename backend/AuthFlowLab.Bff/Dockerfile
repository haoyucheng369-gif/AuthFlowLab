FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY backend/AuthFlowLab.Bff/AuthFlowLab.Bff.csproj backend/AuthFlowLab.Bff/
RUN dotnet restore backend/AuthFlowLab.Bff/AuthFlowLab.Bff.csproj

COPY backend/AuthFlowLab.Bff/ backend/AuthFlowLab.Bff/
RUN dotnet publish backend/AuthFlowLab.Bff/AuthFlowLab.Bff.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/publish .
EXPOSE 8080
ENTRYPOINT ["dotnet", "AuthFlowLab.Bff.dll"]
