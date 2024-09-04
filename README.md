# Disconnected GPO Editor

## Introduction

Disconnected GPO Editor is a launcher for the official Group Policy Manager to bypass the domain joined requirement that is needed when using the official MMC snap-in.  

The tool works by injecting a C# library into MMC that will hook the `GetUserNameExW` API calls to trick GPM into believing that the machine is part of the domain.  Hooks are also placed on the `NtCreateFile` API to redirect file paths that would typically be resolved via DFS to a specific domain controller instead.





