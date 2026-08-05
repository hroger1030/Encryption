# CLAUDE.md

## Project overview

This repository contains a .NET solution for generating random numbers and values.

## Stack

- C#
- Microsoft .NET 8
- Newtonsoft JSON parser
- NUnit tests 
- To be built for a Windows platform

## Development guidance

- Keep changes compatible with .NET 8.
- There should be only one namespace per project, and it should match the project name.
- No private functions allowed. methods should be public to allow unit tests to be written.
- set up functions to use dependency injection to allow for easy testing.
- Prefer small, focused updates to the genetic logic and parser code.
- When changing behavior in the console app, keep the existing JSON parsing flow intact unless there is a specific reason to restructure it.
- If you add new features, update this file to reflect the new workflow.
- Always check for obsolete-API warnings on encryption/hashing APIs (e.g. `SYSLIB0060` on `Rfc2898DeriveBytes`) after building. These are not routine cleanup items — an obsolete crypto primitive can mean a weakened or deprecated algorithm, so treat them as a priority to investigate and fix, not just suppress.

## Non-negotiables

- Don't upgrade any nuget package version without asking first. You can point out out of date packages to the user.
- Don't do write anything to git. You can read all you want, but no writes or commits.
- when refactoring existing code, do not remove comments. They can be updated if needed, but not removed.