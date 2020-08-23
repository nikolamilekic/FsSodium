@echo off

dotnet tool restore
dotnet paket restore
dotnet restore dotnet-fake.csproj
dotnet fake run build.fsx %*
