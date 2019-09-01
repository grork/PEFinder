// Lifted with love from https://stackoverflow.com/a/2864494
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Codevoid.Utility.PEFinder
{
    internal enum MachineType : ushort
    {
        IMAGE_FILE_MACHINE_UNKNOWN = 0,
        IMAGE_FILE_MACHINE_TARGET_HOST = 0x0001,  // Useful for indicating we want to interact with the host and not a WoW guest.
        IMAGE_FILE_MACHINE_I386 = 0x014c,  // Intel 386.
        IMAGE_FILE_MACHINE_R3000 = 0x0162,  // MIPS little-endian, 0x160 big-endian
        IMAGE_FILE_MACHINE_R4000 = 0x0166,  // MIPS little-endian
        IMAGE_FILE_MACHINE_R10000 = 0x0168,  // MIPS little-endian
        IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169,  // MIPS little-endian WCE v2
        IMAGE_FILE_MACHINE_ALPHA = 0x0184,  // Alpha_AXP
        IMAGE_FILE_MACHINE_SH3 = 0x01a2,  // SH3 little-endian
        IMAGE_FILE_MACHINE_SH3DSP = 0x01a3,
        IMAGE_FILE_MACHINE_SH3E = 0x01a4,  // SH3E little-endian
        IMAGE_FILE_MACHINE_SH4 = 0x01a6,  // SH4 little-endian
        IMAGE_FILE_MACHINE_SH5 = 0x01a8,  // SH5
        IMAGE_FILE_MACHINE_ARM = 0x01c0,  // ARM Little-Endian
        IMAGE_FILE_MACHINE_THUMB = 0x01c2,  // ARM Thumb/Thumb-2 Little-Endian
        IMAGE_FILE_MACHINE_ARMNT = 0x01c4,  // ARM Thumb-2 Little-Endian
        IMAGE_FILE_MACHINE_AM33 = 0x01d3,
        IMAGE_FILE_MACHINE_POWERPC = 0x01F0,  // IBM PowerPC Little-Endian
        IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1,
        IMAGE_FILE_MACHINE_IA64 = 0x0200,  // Intel 64
        IMAGE_FILE_MACHINE_MIPS16 = 0x0266,  // MIPS
        IMAGE_FILE_MACHINE_ALPHA64 = 0x0284,  // ALPHA64
        IMAGE_FILE_MACHINE_MIPSFPU = 0x0366,  // MIPS
        IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466,  // MIPS
        IMAGE_FILE_MACHINE_TRICORE = 0x0520,  // Infineon
        IMAGE_FILE_MACHINE_CEF = 0x0CEF,
        IMAGE_FILE_MACHINE_EBC = 0x0EBC,  // EFI Byte Code
        IMAGE_FILE_MACHINE_AMD64 = 0x8664,  // AMD64 (K8)
        IMAGE_FILE_MACHINE_M32R = 0x9041,  // M32R little-endian
        IMAGE_FILE_MACHINE_ARM64 = 0xAA64,  // ARM64 Little-Endian
        IMAGE_FILE_MACHINE_CEE = 0xC0EE
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;    // Magic number
        public ushort e_cblp;     // Bytes on last page of file
        public ushort e_cp;       // Pages in file
        public ushort e_crlc;     // Relocations
        public ushort e_cparhdr;  // Size of header in paragraphs
        public ushort e_minalloc; // Minimum extra paragraphs needed
        public ushort e_maxalloc; // Maximum extra paragraphs needed
        public ushort e_ss;       // Initial (relative) SS value
        public ushort e_sp;       // Initial SP value
        public ushort e_csum;     // Checksum
        public ushort e_ip;       // Initial IP value
        public ushort e_cs;       // Initial (relative) CS value
        public ushort e_lfarlc;   // File address of relocation table
        public ushort e_ovno;     // Overlay number
        public uint e_res1;       // Reserved
        public uint e_res2;       // Reserved
        public ushort e_oemid;    // OEM identifier (for e_oeminfo)
        public ushort e_oeminfo;  // OEM information; e_oemid specific
        public uint e_res3;       // Reserved
        public uint e_res4;       // Reserved
        public uint e_res5;       // Reserved
        public uint e_res6;       // Reserved
        public uint e_res7;       // Reserved
        public int e_lfanew;      // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER
    {
        public MachineType Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS_COMMON
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS32
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS64
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER32
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER64
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
    }

    static class PEInspector
    {
        const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;  // MZ
        const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE00

        const ushort IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B; // PE32
        const ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B; // PE32+

        const ushort IMAGE_FILE_DLL = 0x2000;

        public static bool IsValidPEFile(FileStream stream)
        {
            try
            {
                IMAGE_DOS_HEADER dosHeader = GetDosHeader(stream);
                if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
                {
                    return false;
                }

                IMAGE_NT_HEADERS_COMMON ntHeader = GetCommonNtHeader(stream, dosHeader);
                if (ntHeader.Signature != IMAGE_NT_SIGNATURE)
                {
                    return false;
                }

                switch ((MachineType)ntHeader.FileHeader.Machine)
                {
                    case MachineType.IMAGE_FILE_MACHINE_I386:
                        return IsValidExe32(GetNtHeader32(stream, dosHeader));

                    case MachineType.IMAGE_FILE_MACHINE_IA64:
                    case MachineType.IMAGE_FILE_MACHINE_AMD64:
                        return IsValidExe64(GetNtHeader64(stream, dosHeader));
                }
            }
            catch (InvalidOperationException)
            {
                return false;
            }

            return true;
        }

        static bool IsValidExe32(IMAGE_NT_HEADERS32 ntHeader)
        {
            return ntHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        }

        static bool IsValidExe64(IMAGE_NT_HEADERS64 ntHeader)
        {
            return ntHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        }

        static IMAGE_DOS_HEADER GetDosHeader(Stream stream)
        {
            stream.Seek(0, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_DOS_HEADER>(stream);
        }

        static IMAGE_NT_HEADERS_COMMON GetCommonNtHeader(Stream stream, IMAGE_DOS_HEADER dosHeader)
        {
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_NT_HEADERS_COMMON>(stream);
        }

        static IMAGE_NT_HEADERS32 GetNtHeader32(Stream stream, IMAGE_DOS_HEADER dosHeader)
        {
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_NT_HEADERS32>(stream);
        }

        static IMAGE_NT_HEADERS64 GetNtHeader64(Stream stream, IMAGE_DOS_HEADER dosHeader)
        {
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_NT_HEADERS64>(stream);
        }

        static T ReadStructFromStream<T>(Stream stream)
        {
            int structSize = Marshal.SizeOf(typeof(T));
            IntPtr memory = IntPtr.Zero;

            try
            {
                memory = Marshal.AllocCoTaskMem(structSize);
                if (memory == IntPtr.Zero)
                    throw new InvalidOperationException();

                byte[] buffer = new byte[structSize];
                int bytesRead = stream.Read(buffer, 0, structSize);
                if (bytesRead != structSize)
                    throw new InvalidOperationException();

                Marshal.Copy(buffer, 0, memory, structSize);

                return (T)Marshal.PtrToStructure(memory, typeof(T));
            }
            finally
            {
                if (memory != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(memory);
                }
            }
        }
    }
}