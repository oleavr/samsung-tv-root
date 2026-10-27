using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

internal static class KernelScan
{
    private const int ProtRead = 1;
    private const int MapShared = 1;
    private const int SysMmap2Arm = 192;
    private const long ChunkLength = 0x1000000;
    private const int Overlap = 32;

    public static int Main(string[] arguments)
    {
        if (arguments.Length < 3)
        {
            Console.Error.WriteLine("usage: KernelScan scanhex-many <start> <len> <hex,hex,...> [max] | dump <start> <len> <out>");
            return 2;
        }
        string mode = arguments[0];
        long start = ParseInteger(arguments[1]);
        long length = ParseInteger(arguments[2]);

        string devicePath = Environment.GetEnvironmentVariable("UEP_DEVICE") ?? "/dev/sdp_hwmem";
        int device = Open(devicePath, 0);
        if (device < 0)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "open " + devicePath + " failed");
        try
        {
            switch (mode)
            {
                case "scanhex-many":
                    return Scan(device, start, length, ParseNeedles(arguments[3]),
                        arguments.Length >= 5 ? (int)ParseInteger(arguments[4]) : 64);
                case "dump":
                    return Dump(device, start, length, arguments[3]);
                default:
                    Console.Error.WriteLine("unknown mode: {0}", mode);
                    return 2;
            }
        }
        finally
        {
            close(device);
        }
    }

    private static long ParseInteger(string text)
    {
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return Convert.ToInt64(text.Substring(2), 16);
        return Convert.ToInt64(text, 10);
    }

    private static byte[][] ParseNeedles(string text)
    {
        string[] parts = text.Split(',');
        var needles = new byte[parts.Length][];
        for (int i = 0; i < parts.Length; i++)
        {
            needles[i] = new byte[parts[i].Length / 2];
            for (int j = 0; j < needles[i].Length; j++)
                needles[i][j] = Convert.ToByte(parts[i].Substring(j * 2, 2), 16);
        }
        return needles;
    }

    private static unsafe int Scan(int device, long start, long length, byte[][] needles, int maxMatches)
    {
        int hits = 0;
        for (long done = 0; done < length; done += ChunkLength - Overlap)
        {
            long chunkLength = Math.Min(ChunkLength, length - done);
            long chunkStart = start + done;
            long pageStart = chunkStart & ~0xFFFL;
            chunkLength += chunkStart - pageStart;
            IntPtr mapping = SyscallMmap2(SysMmap2Arm, IntPtr.Zero, new UIntPtr((ulong)chunkLength), ProtRead, MapShared, device, (uint)(pageStart >> 12));
            if (mapping == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"mmap2 phys=0x{pageStart:x} failed");
            try
            {
                byte* bytes = (byte*)mapping;
                for (long offset = 0; offset < chunkLength - Overlap; offset++)
                {
                    for (int n = 0; n < needles.Length; n++)
                    {
                        byte[] needle = needles[n];
                        bool match = true;
                        for (int j = 0; j < needle.Length; j++)
                        {
                            if (bytes[offset + j] != needle[j])
                            {
                                match = false;
                                break;
                            }
                        }
                        if (!match)
                            continue;
                        Console.WriteLine("match needle[{0}]={1} physical=0x{2:x}", n,
                            BitConverter.ToString(needle).Replace("-", "").ToLowerInvariant(), pageStart + offset);
                        if (++hits >= maxMatches)
                        {
                            Console.WriteLine("hits={0} (truncated)", hits);
                            return 0;
                        }
                    }
                }
            }
            finally
            {
                munmap(mapping, new UIntPtr((ulong)chunkLength));
            }
        }
        Console.WriteLine("hits={0}", hits);
        return hits == 0 ? 1 : 0;
    }

    private static int Dump(int device, long start, long length, string outputPath)
    {
        using (var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
        {
            for (long done = 0; done < length; done += ChunkLength)
            {
                long chunkLength = Math.Min(ChunkLength, length - done);
                long chunkStart = start + done;
                IntPtr mapping = SyscallMmap2(SysMmap2Arm, IntPtr.Zero, new UIntPtr((ulong)chunkLength), ProtRead, MapShared, device, (uint)(chunkStart >> 12));
                if (mapping == new IntPtr(-1))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), $"mmap2 phys=0x{chunkStart:x} failed");
                try
                {
                    var chunk = new byte[chunkLength];
                    Marshal.Copy(mapping, chunk, 0, chunk.Length);
                    output.Write(chunk, 0, chunk.Length);
                }
                finally
                {
                    munmap(mapping, new UIntPtr((ulong)chunkLength));
                }
            }
        }
        Console.WriteLine("dumped 0x{0:x} bytes from physical=0x{1:x} to {2}", length, start, outputPath);
        return 0;
    }

    [DllImport("libc", EntryPoint = "syscall", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    private static extern IntPtr SyscallMmap2(int number, IntPtr address, UIntPtr length, int protection, int flags, int fileDescriptor, uint pageOffset);

    [DllImport("libc", SetLastError = true)]
    private static extern int munmap(IntPtr address, UIntPtr length);

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fileDescriptor);
}
