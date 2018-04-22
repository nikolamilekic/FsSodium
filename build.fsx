#r "paket:
nuget Fake.Core.ReleaseNotes prerelease //
nuget Fake.Core.Target prerelease //
nuget Fake.DotNet.AssemblyInfoFile //
nuget Fake.DotNet.Cli prerelease //
nuget Fake.DotNet.Paket prerelease //
nuget Fake.IO.FileSystem prerelease //
nuget Fake.Runtime prerelease //
nuget Fake.Tools.Git prerelease //"
#load "./.fake/build.fsx/intellisense.fsx"

open System.IO

open Fake.Core
open Fake.Core.Target
open Fake.Core.TargetOperators
open Fake.DotNet
open Fake.IO
open Fake.IO.Globbing.Operators
open Fake.IO.FileSystemOperators
open Fake.Runtime
open Fake.Tools.Git

let productName = "FsSodium"
let releaseNotes = ReleaseNotes.load "RELEASE_NOTES.md"

Target.create "Clean" <| fun _ ->
    Seq.allPairs [|"src"; "tests"|] [|"bin"; "obj"|]
    |> Seq.collect (fun (x, y) -> !!(sprintf "%s/**/%s" x y))
    |> Seq.append [|"bin"; "obj"|]
    |> Shell.DeleteDirs
Target.create "Build" <| fun _ -> DotNet.build id (productName + ".sln")
Target.create "Test" <| fun _ ->
    !! "tests/*.Tests/"
    |> Seq.map (fun path ->
        DotNet.exec
            (fun o -> { o with WorkingDirectory = path }) "run" "-c Release")
    |> List.ofSeq
    |> List.iter (fun r -> if r.ExitCode <> 0 then failwith "Tests failed")
Target.create "BumpVersion" <| fun _ ->
    !! "src/**/*.fsproj"
    |> Seq.iter (fun projectPath ->
        let projectName = Path.GetFileNameWithoutExtension projectPath
        let attributes = [
            AssemblyInfo.Title projectName
            AssemblyInfo.Product productName
            AssemblyInfo.Version releaseNotes.AssemblyVersion
            AssemblyInfo.FileVersion releaseNotes.AssemblyVersion
        ]
        AssemblyInfoFile.createFSharp
            (Path.GetDirectoryName projectPath </> "AssemblyInfo.fs")
            attributes)
    let appveyorPath = "appveyor.yml"
    File.ReadAllLines appveyorPath
    |> Seq.map (function
        | line when line.StartsWith "version:" ->
            sprintf "version: %s" releaseNotes.NugetVersion
        | line -> line)
    |> fun lines -> File.WriteAllLines(appveyorPath, lines)
    Staging.stageAll ""
    Commit.exec "" (sprintf "Bump version to %s" releaseNotes.NugetVersion)
Target.create "Release" <| fun _ ->
    let remote = Environment.environVarOrFail "FsSodiumRemote"
    Branches.pushTag "" remote releaseNotes.NugetVersion
Target.create "CopyBinaries" <| fun _ ->
    !! "src/**/*.fsproj"
    |>  Seq.map (fun projectPath ->
        (Path.GetDirectoryName projectPath) </> "bin/Release",
        "bin" </> (Path.GetFileNameWithoutExtension projectPath))
    |>  Seq.iter (fun (source, target) ->
        Shell.CopyDir target source (fun _ -> true))
Target.create "Nuget" <| fun _ ->
    let isAppVeyor = Environment.environVarAsBool "APPVEYOR"
    let fromTag = Environment.environVarAsBool "APPVEYOR_REPO_TAG"
    if isAppVeyor && (not fromTag) then () else
    Paket.pack (fun p ->
        { p with
            OutputPath = "bin"
            Version = releaseNotes.NugetVersion
            ReleaseNotes = String.toLines releaseNotes.Notes})
Target.create "AppVeyor" DoNothing

Target.create "Rebuild" DoNothing

"Clean"
    ?=> "Build"
    ==> "CopyBinaries"
    ==> "Test"
    ==> "Rebuild"
    ==> "Nuget"
    ==> "AppVeyor"

"Clean" ==> "Rebuild"
"Rebuild" ==> "Release"

runOrDefault "Test"
