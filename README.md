PEFinder
===========

This tool is intended to assist in cleaning up large collections of files by finding & moving files with the standard PE Header.

This tool attempts this as three phases:
1. Enumerate all the files in a folder tree
2. Search each of the discovered files for any files that match a standard PE header
3. Take all the copies of the files that have the PE Header, and move all but one of them to a target destination folder.

With each step, and often within each step, the state is captured of what has been discovered & inspected up to that point. Additionally, any time you terminate the tool through the use of `Ctrl+C`, state will be saved to allow you to pick up where you left off.

Depending on the number of files, speed of the disk where the files are located, performance of the computer, and the amount of RAM available, this process can take a long time to complete.

This has been tested on Windows 10.

## Usage ##
The tool will print it's usage on the command line if no parameters are passed.

For refrence:

| Parameter                    | Description                                                                                     |
|------------------------------|-------------------------------------------------------------------------------------------------|
| `/r[oot]`                    | The root path where to start this search from.                                                  |
| `/res[ume]`                  | Loads the state file, and continues from where it had been stopped. This will check the file system for new files, and continue identifying files that haven't been checked yet. |
| `/st[ate]`                   | File path for state to be saved. If not specfied, saves to `State.xml` in the working directory |
| `/skip:`                     | Skips checking the file system and only uses saved tate to determine work                       |
| `/d[estinationroot]:`        | Full path to a destination for any PE Files that are found. If not supplied, no files will be moved |

Example Usage:

`dotnet PEFinder.dll /root f:\Data`

This will start processing the folder tree starting in `f:\data`, and save it's process in the directory where you executed the command in as it progresses.

`dotnet PEFinder.dll /root f:\data /resume`

Will start processing the folder tree starting in `f:\data`, and will try to load any data `State.xml`, and compare that against the file system

## Resuming ##
When the `/resume` parameter is used, the tool will load the data from the `State.xml` first, compare it against the file system (e.g. reprocess the whole tree), and add anything that is not in the previously state. After that has completed, it will start checking the files. **If** the state file has some PE headers already inspected, it will **not** regenerate them, and start at the first file that does not have an inspection state.

If you had started searching during your previous execution, and you know you have not added any files into the folder tree, you can add `/skip` to the parameters, and this will not consult the file system for any changes and jump straight to the file inspection.

## PE File Relocation ##
Becuase the initial use case of this tool was working with data that was impossible to replace if lost, the relocation attempts to be _non destructive_. That is to say, it doesn't delete any of the data.

PE File relocation only happens if the `/destinationroot` parameter is supplied. If it is, the files are _moved_ to a new directory following the original folder structure, reparented under the destination root. This means that it's possible to move the PE Files out of the way, and preserve the data in case of something _really bad_ happening.

It should be noted that if you put the destination on a separate physical drive, the duration of the move phase will drastically increase since it has to physically move the files, rather than just update the file system in place.