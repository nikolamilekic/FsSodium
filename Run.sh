#!/usr/bin/env bash

set -eu
set -o pipefail

dotnet tool restore
dotnet paket restore
dotnet fake run build.fsx --target run
