#load ".fake/build.fsx/intellisense.fsx"

Fake.Core.Target.initEnvironment ()

module CustomTargetOperators =
    //nuget Fake.Core.Target

    open Fake.Core.TargetOperators

    let (==>) xs y = xs |> Seq.iter (fun x -> x ==> y |> ignore)
    let (?=>) xs y = xs |> Seq.iter (fun x -> x ?=> y |> ignore)

module FinalVersion =
    //nuget Fake.IO.FileSystem

    open System.Text.RegularExpressions
    open Fake.IO
    open Fake.IO.Globbing.Operators
    open Fake.Core

    let pathToAssemblyInfoFile =
        lazy
        !! "src/FsSodium/obj/Release/**/FsSodium.AssemblyInfo.fs"
        |> Seq.head

    let (|Regex|_|) pattern input =
        let m = Regex.Match(input, pattern)
        if m.Success then Some(List.tail [ for g in m.Groups -> g.Value ])
        else None

    let finalVersion =
        lazy
        pathToAssemblyInfoFile.Value
        |> File.readAsString
        |> function
            | Regex "AssemblyInformationalVersionAttribute\(\"(.+)\"\)>]" [ version ] ->
                SemVer.parse version
            | _ -> failwith "Could not parse assembly version"

module ReleaseNotesParsing =
    //nuget Fake.Core.ReleaseNotes

    open System
    open Fake.Core

    let releaseNotesFile = "RELEASE_NOTES.md"
    let releaseNotes =
        lazy
        (ReleaseNotes.load releaseNotesFile).Notes
        |> String.concat Environment.NewLine

module Clean =
    //nuget FSharpPlus
    //nuget Fake.IO.FileSystem

    open Fake.IO
    open Fake.IO.Globbing.Operators
    open Fake.Core
    open FSharpPlus

    Target.create "Clean" <| fun _ ->
        lift2 tuple2 [|"src"; "tests"|] [|"bin"; "obj"|]
        >>= fun (x,y) -> !!(sprintf "%s/**/%s" x y) |> toSeq
        |> plus ([|"bin"; "obj"|] |> toSeq)
        |> Shell.deleteDirs

        Shell.cleanDir "publish"

module Build =
    //nuget Fake.DotNet.Cli
    //nuget Fake.BuildServer.AppVeyor

    open Fake.DotNet
    open Fake.Core
    open Fake.Core.TargetOperators
    open Fake.BuildServer

    open FinalVersion

    let projectToBuild = "FsSodium.sln"

    Target.create "Build" <| fun _ ->
        DotNet.build id projectToBuild

        if AppVeyor.detect() then
            let finalVersion = finalVersion.Value
            let appVeyorVersion =
                sprintf
                    "%d.%d.%d.%s"
                    finalVersion.Major
                    finalVersion.Minor
                    finalVersion.Patch
                    AppVeyor.Environment.BuildNumber

            AppVeyor.updateBuild (fun p -> { p with Version = appVeyorVersion })

    "Clean" ?=> "Build"

module Pack =
    //nuget Fake.DotNet.Cli

    open Fake.DotNet
    open Fake.Core

    open CustomTargetOperators
    open ReleaseNotesParsing

    let projectToPack = "FsSodium.sln"

    Target.create "Pack" <| fun _ ->
        let newBuildProperties = [ "PackageReleaseNotes", releaseNotes.Value ]
        DotNet.pack
            (fun p ->
                { p with
                    OutputPath = Some (__SOURCE_DIRECTORY__ + "/publish")
                    NoBuild = true
                    MSBuildParams =
                        { p.MSBuildParams with
                            Properties =
                                newBuildProperties @ p.MSBuildParams.Properties }})
            projectToPack

    [ "Clean"; "Build" ] ==> "Pack"

module Test =
    //nuget FSharpPlus
    //nuget Fake.IO.FileSystem
    //nuget Fake.DotNet.Testing.Expecto

    open System.IO
    open Fake.Core
    open Fake.Core.TargetOperators
    open Fake.IO.Globbing.Operators
    open Fake.DotNet.Testing
    open FSharpPlus

    Target.create "Test" <| fun _ ->
        !! "tests/**/*.fsproj"
        |> toSeq
        >>= fun projectPath ->
            let projectName = Path.GetFileNameWithoutExtension projectPath
            !! (sprintf "tests/%s/bin/release/**/%s.dll" projectName projectName)
            |> toSeq
        |> Expecto.run id
    "Build" ==> "Test"

module TestSourceLink =
    //nuget FSharpPlus
    //nuget Fake.IO.FileSystem
    //nuget Fake.DotNet.Cli

    open Fake.Core
    open Fake.Core.TargetOperators
    open Fake.IO.Globbing.Operators
    open Fake.DotNet
    open FSharpPlus

    Target.create "TestSourceLink" <| fun _ ->
        !! "publish/*.nupkg"
        |> flip Seq.iter <| fun p ->
            DotNet.exec
                id
                "sourcelink"
                (sprintf "test %s" p)
            |> fun r -> if not r.OK then failwithf "Source link check for %s failed." p

    "Pack" ==> "TestSourceLink"

module UploadArtifactsToGitHub =
    //nuget Fake.Api.GitHub
    //nuget Fake.IO.FileSystem
    //nuget Fake.BuildServer.AppVeyor

    open Fake.Core
    open Fake.Api
    open Fake.IO.Globbing.Operators
    open Fake.BuildServer

    open CustomTargetOperators
    open FinalVersion
    open ReleaseNotesParsing

    let productName = "FsSodium"
    let gitOwner = "nikolamilekic"

    Target.create "UploadArtifactsToGitHub" <| fun _ ->
        let finalVersion = finalVersion.Value
        if AppVeyor.detect() && finalVersion.PreRelease.IsNone then
            let token = Environment.environVarOrFail "GitHubToken"
            GitHub.createClientWithToken token
            |> GitHub.createRelease
                gitOwner
                productName
                (finalVersion.NormalizeToShorter())
                (fun o ->
                    { o with
                        Body = releaseNotes.Value
                        Prerelease = (finalVersion.PreRelease <> None)
                        TargetCommitish = AppVeyor.Environment.RepoCommit })
            |> GitHub.uploadFiles (!! "publish/*.nupkg" ++ "publish/*.zip")
            |> GitHub.publishDraft
            |> Async.RunSynchronously

    [ "Pack"; "Test"; "TestSourceLink" ] ==> "UploadArtifactsToGitHub"

module UploadPackageToNuget =
    //nuget Fake.DotNet.Paket
    //nuget Fake.BuildServer.AppVeyor

    open Fake.Core
    open Fake.DotNet
    open Fake.BuildServer

    open FinalVersion
    open CustomTargetOperators

    Target.create "UploadPackageToNuget" <| fun _ ->
        if AppVeyor.detect() && finalVersion.Value.PreRelease.IsNone then
            Paket.push <| fun p ->
                { p with
                    ToolType = ToolType.CreateLocalTool()
                    WorkingDir = __SOURCE_DIRECTORY__ + "/publish" }

    [ "Pack"; "Test"; "TestSourceLink" ] ==> "UploadPackageToNuget"

module Release =
    //nuget Fake.Tools.Git

    open Fake.Core
    open Fake.Tools

    open CustomTargetOperators

    let gitHome = "git@github.com:nikolamilekic/FsSodium.git"

    Target.create "Release" <| fun _ ->
        Git.CommandHelper.directRunGitCommandAndFail
            ""
            (sprintf "push -f %s HEAD:release" gitHome)

    [ "Clean"; "Build"; "Test" ] ==> "Release"

module AppVeyor =
    open Fake.Core

    open CustomTargetOperators

    Target.create "AppVeyor" ignore
    [ "UploadArtifactsToGitHub"; "UploadPackageToNuget" ]
    ==> "AppVeyor"

module Default =
    open Fake.Core

    open CustomTargetOperators

    Target.create "Default" ignore
    [ "Build"; "Test" ] ==> "Default"

    Target.runOrDefault "Default"
