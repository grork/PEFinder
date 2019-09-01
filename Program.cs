using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Threading;
using System.Xml;

namespace Codevoid.Utility.PEFinder
{
    class Program
    {
        /// <summary>
        /// The number of files to inspect before saving state "mid stream"
        /// </summary>
        private const ulong NUMBER_OF_INSPECTED_FILES_BEFORE_SAVING_STATE = 50000;

        static void Main(string[] args)
        {
            var app = new Program();
            var parsedArgs = app.ParseArgs(args);
            if (!parsedArgs)
            {
                Program.PrintUsage();
                return;
            }

            if(!app.ValidateReadyToBegin())
            {
                return;
            }

            // Reduce flicker when we update the processed file count
            Console.CursorVisible = false;

            app.ListenForCancellation();
            app.Begin();
        }

        private DirectoryInfo _root;
        private DirectoryInfo _peFilesDestinationRoot;
        private DirectoryNode _originalsNode = new DirectoryNode(String.Empty, null);
        private bool _resume;
        private string _statePath = "state.xml";
        private bool _skipFileSystemCheck;
        private readonly Queue<FileNode> _itemsRequiringInspecting = new Queue<FileNode>(5000);
        private readonly IList<FileNode> _peFiles = new List<FileNode>(5000);
        private readonly string _rootPathPrefix = String.Empty;
        private readonly CancellationTokenSource _cancellationSource = new CancellationTokenSource();

        private Program()
        {
            // To support extra long (> MAX_PATH) paths on windows, paths need
            // to be prefixed with the NT Object format prefix.
            if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                this._rootPathPrefix = @"\\?\";
            }
        }

        private bool ParseArgs(string[] args)
        {
            if (args.Length < 2)
            {
                return false;
            }

            for (var argIndex = 0; argIndex < args.Length; argIndex++)
            {
                var argument = args[argIndex].ToLowerInvariant();
                switch (argument)
                {
                    case "/r":
                    case "/root":
                    case "/o":
                    case "/originals":
                        argIndex++;
                        this._root = new DirectoryInfo(this._rootPathPrefix + args[argIndex]);
                        break;

                    case "/res":
                    case "/resume":
                        this._resume = true;
                        break;

                    case "/st":
                    case "/state":
                        argIndex++;
                        this._statePath = args[argIndex];
                        break;

                    case "/skip":
                        this._skipFileSystemCheck = true;
                        break;

                    case "/d":
                    case "/destinationroot":
                        argIndex++;
                        this._peFilesDestinationRoot = new DirectoryInfo(this._rootPathPrefix + args[argIndex]);
                        break;

                    default:
                        break;
                }
            }

            return true;
        }

        private bool ValidateReadyToBegin()
        {
            if(!this._root.Exists)
            {
                Console.WriteLine($"Root directory '${this._root.FullName}' wasn't found");
                return false;
            }

            if(this._peFilesDestinationRoot != null && !this._peFilesDestinationRoot.Exists)
            {
                try
                {
                    this._peFilesDestinationRoot.Create();
                }
                catch(IOException)
                {
                    Console.WriteLine($"Unable to create directory for found PE Files at '${this._peFilesDestinationRoot.FullName}'");
                    return false;
                }
            }

            return true;
        }

        private void ListenForCancellation()
        {
            Console.CancelKeyPress += this.Console_CancelKeyPress;
        }

        private void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            lock (this)
            {
                this._cancellationSource.Cancel();
                e.Cancel = true;
            }
        }

        private void Begin()
        {
            Program.PrintHeader();

            Console.WriteLine("Root: {0}", this._root);

            DateTime start = DateTime.Now;
            Console.WriteLine("Started At: {0}", start);

            if (this._resume && File.Exists(this._statePath))
            {
                Console.WriteLine("Loading Saved State");
                this.LoadState(this._statePath);
                Console.WriteLine("State Loaded In: {0}", DateTime.Now - start);
            }
            else if (this._resume)
            {
                Console.WriteLine("State File not found, loading information from the file system");
            }

            ulong addedFileCount = 0;
            var cancelled = false;

            // Discover files from the file system
            if (!this._skipFileSystemCheck)
            {
                var originalsDiscoverer = new FileDiscoverer(root: this._root,
                                        peFileDestinationRoot: this._peFilesDestinationRoot,
                                             sourcedFromOriginals: true,
                                             cancellationToken: this._cancellationSource.Token);
                originalsDiscoverer.FileDiscovered += this.AddFileToFoundLIstListOrQueueForInspection;
                originalsDiscoverer.DiscoverFiles();

                addedFileCount += originalsDiscoverer.DiscoveredFileCount;
                this._originalsNode = originalsDiscoverer.RootNode;

                if (this._cancellationSource.IsCancellationRequested)
                {
                    Console.WriteLine();
                    Console.WriteLine("Execution cancelled: Saving state for resuming later");
                }

                if (addedFileCount > 0)
                {
                    Program.UpdateConsole("New Files added: {0}", addedFileCount.ToString());
                }

                Console.WriteLine();
                Console.WriteLine("State Validated in: {0}", DateTime.Now - start);
            }

            if (addedFileCount > 0)
            {
                this.SaveCurrentStateToDisk();
            }

            // If we were cancelled, lets not continue on to process
            // the files 'cause the customer is implying we
            // should give up
            if (cancelled)
            {
                return;
            }

            ulong filesInspected = 0;
            if (this._itemsRequiringInspecting.Count > 0)
            {
                var inspectionStart = DateTime.Now;
                Console.WriteLine("Inspecting {0} File(s). Starting at: {1}", this._itemsRequiringInspecting.Count, inspectionStart);

                ulong filesInspectedSinceLastSave = 0;

                // Any items that require inspection have been added to the queue
                // or been placed in the inspected list, so lets inspect the ones
                // that require work
                while (this._itemsRequiringInspecting.Count > 0)
                {
                    if(filesInspectedSinceLastSave > Program.NUMBER_OF_INSPECTED_FILES_BEFORE_SAVING_STATE)
                    {
                        this.SaveCurrentStateToDisk();
                        filesInspectedSinceLastSave = 0;
                    }

                    var fileToInspect = this._itemsRequiringInspecting.Dequeue();

                    this.InspectFileAndUpdateState(fileToInspect);

                    filesInspected++;
                    filesInspectedSinceLastSave++;

                    lock (this)
                    {
                        if (this._cancellationSource.IsCancellationRequested)
                        {
                            Console.WriteLine();
                            cancelled = true;
                            break;
                        }
                    }
                }

                if (filesInspected > 0)
                {
                    this.SaveCurrentStateToDisk();
                }
            }
            else
            {
                Console.WriteLine("No files needed inspecting");
            }

            if (cancelled)
            {
                return;
            }

            Console.WriteLine();
            Console.WriteLine("Inspecting {0} file(s) took {1}", filesInspected, DateTime.Now - start);

            if (this._peFiles.Count == 0)
            {
                Console.WriteLine("No duplicate files found");
                return;
            }

            Console.WriteLine("Files with PE Headers: {0}", this._peFiles.Count);

            // If theres no destination directory, then we can't move anything
            if (this._peFilesDestinationRoot != null)
            {
                ulong filesMoved = 0;
                this._peFilesDestinationRoot.Create();
                foreach(FileNode peFile in this._peFiles)
                {
                    if(this.MovePEFilesToDestination(peFile))
                    {
                        filesMoved += 1;
                    }

                    lock (this)
                    {
                        if (this._cancellationSource.IsCancellationRequested)
                        {
                            Console.WriteLine();
                            cancelled = true;
                            break;
                        }
                    }
                }

                Console.WriteLine();
                Console.WriteLine("Files moved: {0}", filesMoved);
            }
            else
            {
                Console.WriteLine("Not moving files, so printing PE file list:");
                foreach(FileNode peFile in this._peFiles)
                {
                    Console.WriteLine(peFile.FullPath);
                }
            }
        }

        private bool MovePEFilesToDestination(FileNode peFile)
        {
            var destinationSubPath = Program.GetPathForDirectory(peFile.Parent);
            var treeSubPath = Path.Combine(destinationSubPath, peFile.Name);

            var sourceFilePath = Path.Combine(this._root.FullName, treeSubPath);
            if(!File.Exists(sourceFilePath))
            {
                Console.WriteLine("Skipping File, source no longer present: {0}", sourceFilePath);
                return false;
            }

            var destinationFilePath = Path.Combine(this._peFilesDestinationRoot.FullName, treeSubPath);
            this._peFilesDestinationRoot.CreateSubdirectory(destinationSubPath);
            File.Move(sourceFilePath, destinationFilePath);
        
            Program.UpdateConsole("Moved to duplicate directory: {0}", sourceFilePath);

            return true;
        }

        private void InspectFileAndUpdateState(FileNode fileToInspect)
        {
            var filePath = fileToInspect.FullPath;
            Program.UpdateConsole("Inspecting File: {0}", filePath);

            try
            {
                using (var fileStream = File.OpenRead(filePath))
                {
                    fileToInspect.HasPEHeader = PEInspector.IsValidPEFile(fileStream);
                    fileToInspect.Inspected = true;
                }
            }
            catch(SecurityException)
            {
                return;
            }
            catch(FileNotFoundException)
            {
                return;
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine();
                Console.WriteLine("Couldn't inspect: {0}", filePath);
                return;
            }
            catch (IOException)
            {
                Console.WriteLine();
                Console.WriteLine("Couldn't inspect: {0}", filePath);
                return;
            }

            this.AddFileToFoundLIstListOrQueueForInspection(this, fileToInspect);
        }

        private void AddFileToFoundLIstListOrQueueForInspection(object _, FileNode file)
        {
            if (!file.Inspected)
            {
                this._itemsRequiringInspecting.Enqueue(file);
                return;
            }

            if(!file.HasPEHeader)
            {
                return;
            }

            this._peFiles.Add(file);
        }

        #region State Saving
        private void SaveCurrentStateToDisk()
        {
            // Write the loaded data to disk
            var state = new XmlDocument();
            var rootOfState = state.AppendChild(state.CreateElement("State")) as XmlElement;
            rootOfState.SetAttribute("GeneratedAt", DateTime.Now.ToString());

            var originalsState = rootOfState.AppendChild(state.CreateElement("Originals")) as XmlElement;
            Program.AddFilesIntoSavedState(this._originalsNode.Directories.Values, this._originalsNode.Files.Values, originalsState);

            state.Save(this._statePath);
        }

        private static void AddFilesIntoSavedState(ICollection<DirectoryNode> directories, ICollection<FileNode> files, XmlElement parent)
        {
            foreach (var dn in directories)
            {
                var dirElement = parent.OwnerDocument.CreateElement("Folder");

                Program.AddFilesIntoSavedState(dn.Directories.Values, dn.Files.Values, dirElement);

                // If we have a directory with no children
                // then there is no point in persisting this into
                // our state state
                if (dirElement.ChildNodes.Count == 0)
                {
                    continue;
                }

                dirElement.SetAttribute("Name", dn.Name);
                parent.AppendChild(dirElement);
            }

            foreach (var file in files)
            {
                var fileElement = parent.OwnerDocument.CreateElement("File");
                fileElement.SetAttribute("Name", file.Name);
                fileElement.SetAttribute("Inspected", file.Inspected.ToString());
                fileElement.SetAttribute("HasPEHeader", file.HasPEHeader.ToString());

                parent.AppendChild(fileElement);
            }
        }
        #endregion State Saving

        #region State Loading
        private void LoadState(string path)
        {
            var state = new XmlDocument();
            try
            {
                state.Load(path);
            }
            catch
            {
                Console.WriteLine("Invalid State file - restarting from clean state");
                return;
            }

            var rootOfState = state.DocumentElement as XmlElement;

            var originalsNodes = rootOfState.GetElementsByTagName("Originals");
            var originals = new DirectoryNode(String.Empty, null);
            this.ProcessNodes(originals, originalsNodes[0].ChildNodes, sourcedFromOriginalsTree: true);

            var duplicateNodes = rootOfState.GetElementsByTagName("DuplicateCandidates");
            var duplicateCandidates = new DirectoryNode(String.Empty, null);
            this.ProcessNodes(duplicateCandidates, duplicateNodes[0].ChildNodes);

            this._originalsNode = originals;
        }

        private void ProcessNodes(DirectoryNode parent, XmlNodeList children, bool sourcedFromOriginalsTree = false)
        {
            foreach (XmlNode n in children)
            {
                XmlElement item = n as XmlElement;

                switch (item.Name)
                {
                    case "Folder":
                        var newFolder = new DirectoryNode(item.GetAttribute("Name"), parent);
                        this.ProcessNodes(newFolder, item.ChildNodes, sourcedFromOriginalsTree);
                        parent.Directories[newFolder.Name] = newFolder;
                        break;

                    case "File":
                        var fileName = item.GetAttribute("Name");
                        var inspected = Boolean.Parse(item.GetAttribute("Inspected"));
                        var hasPEHeader = Boolean.Parse(item.GetAttribute("HasPEHeader"));

                        var fullPath = Path.Combine(this._root.FullName, Program.GetPathForDirectory(parent), fileName);
                        var newFile = new FileNode(fileName, fullPath, parent)
                        {
                            Inspected = inspected,
                            HasPEHeader = hasPEHeader
                        };

                        parent.Files[fileName] = newFile;

                        this.AddFileToFoundLIstListOrQueueForInspection(this, newFile);
                        break;
                }
            }
        }
        #endregion State Loading

        #region Utility
        private static void UpdateConsole(string message, string data)
        {
            Console.SetCursorPosition(0, Console.CursorTop);

            // If the output is too large to fit on one line, lets
            // trim the *Beginning* of the data so we see the end
            // e.g. to see the filename rather than some repeated
            // part of a file path
            var totalLength = message.Length + data.Length;
            if (totalLength > Console.BufferWidth)
            {
                var excess = totalLength - Console.BufferWidth;
                if (excess < data.Length)
                {
                    data = data.Remove(0, excess);
                }
            }

            if(totalLength < Console.BufferWidth)
            {
                // Pad the rest of the data with spaces
                data = data + new String(' ', Console.BufferWidth - totalLength);
            }

            Console.Write(message, data);
        }

        private static void PrintUsage()
        {
            Program.PrintHeader();

            Console.WriteLine("Usage");
            Console.WriteLine("=====");
            Console.WriteLine("dotnet PEFinder.dll /r[oot]:   The root path where to start this search from.");
            Console.WriteLine();
            Console.WriteLine("Optional:");
            Console.WriteLine("/res[ume]: Loads the state file, and continues from where it was. This will check the file system for new files");
            Console.WriteLine("/st[ate]:  File path for state to be saved. If not specified, saves 'State.xml' in the working directory");
            Console.WriteLine("/skip:     Skips checking the file system and only uses the saved state to determine work");
            Console.WriteLine("/d[estinationroot]: Full path to a directory root to exclude");
        }

        private static void PrintHeader()
        {
            Console.WriteLine("PEFinder -- Scans a file tree and moves any files that have a PE Header");
            Console.WriteLine("Copyright 2019, Dominic Hopton");
            Console.WriteLine();
        }

        private static string GetPathForDirectory(DirectoryNode dn)
        {
            var components = new List<string>();

            while (dn != null && !String.IsNullOrEmpty(dn.Name))
            {
                components.Insert(0, dn.Name);
                dn = dn.Parent;
            }

            return String.Join(Path.DirectorySeparatorChar, components);
        }
        #endregion Utility
    }
}
