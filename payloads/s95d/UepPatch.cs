using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

internal static class UepPatch
{
    private const long PhysToVirt = 0xA0000000;
    private const int ProtRead = 1;
    private const int ProtWrite = 2;
    private const int MapShared = 1;
    private const int SysMmap2Arm = 192;
    private const uint PrologueMoveIpSp = 0xE1A0C00D;
    private const string SavedValuePath = "/home/owner/share/tmp/sdk_tools/kuep/uep_status.bin";

    private static readonly byte[] DisabledMessage = Encoding.ASCII.GetBytes("[%s] UEP has been disabled");

    public static int Main(string[] arguments)
    {
        if (arguments.Length != 1 ||
            (arguments[0] != "on" && arguments[0] != "off" && arguments[0] != "status"))
        {
            Console.Error.WriteLine("usage: UepPatch on|off|status");
            return 2;
        }
        string mode = arguments[0];

        Range kernelCode = ReadIoMemRange("Kernel code");
        Range kernelRodata = ReadIoMemRange("Kernel rodata");
        Range kernelData = ReadIoMemRange("Kernel data");
        Console.WriteLine("kernel code   {0:x}-{1:x}", kernelCode.Start, kernelCode.End);
        Console.WriteLine("kernel rodata {0:x}-{1:x}", kernelRodata.Start, kernelRodata.End);
        Console.WriteLine("kernel data   {0:x}-{1:x}", kernelData.Start, kernelData.End);

        string devicePath = Environment.GetEnvironmentVariable("UEP_DEVICE") ?? "/dev/sdp_hwmem";
        int device = OpenDevice(devicePath, OpenReadWrite);
        try
        {
            long statusWord = FindStatusWord(device, kernelRodata, kernelCode, kernelData);
            uint current = ReadWords(device, statusWord, 1)[0];
            Console.WriteLine("status word phys=0x{0:x} virt=0x{1:x} value={2}", statusWord, statusWord + PhysToVirt, current);
            bool disabled = current == 0;

            if (mode == "status")
                return disabled ? 10 : 11;
            if (mode == "on")
                return DisableUep(device, statusWord, disabled);
            return EnableUep(device, statusWord, disabled);
        }
        finally
        {
            CloseDevice(device);
        }
    }

    private static Range ReadIoMemRange(string label)
    {
        foreach (string line in File.ReadAllLines("/proc/iomem"))
        {
            string trimmed = line.Trim();
            if (!trimmed.EndsWith(": " + label, StringComparison.Ordinal))
                continue;
            int dash = trimmed.IndexOf('-');
            int space = trimmed.IndexOf(' ', dash);
            long start = Convert.ToInt64(trimmed.Substring(0, dash), 16);
            long end = Convert.ToInt64(trimmed.Substring(dash + 1, space - dash - 1), 16);
            return new Range { Start = start, End = end };
        }
        throw new InvalidOperationException("no " + label + " range in /proc/iomem");
    }

    private static long FindStatusWord(int device, Range rodata, Range code, Range data)
    {
        long reference = FindStringReference(device, rodata, DisabledMessage);
        List<long> sites = FindReferenceSites(device, code, reference);
        if (sites.Count != 1)
            throw new InvalidOperationException("expected exactly one reference site for the disable message; aborting");
        Console.WriteLine("disable-print site phys=0x{0:x}", sites[0]);
        List<long> candidates = FindZeroedGlobals(device, code, data, sites[0]);
        if (candidates.Count != 1)
            throw new InvalidOperationException("status word not uniquely identified; aborting");
        return candidates[0];
    }

    private static long FindStringReference(int device, Range rodata, byte[] message)
    {
        byte[] blob = MapPhysicalRange(device, rodata, ProtRead, out long blobBase);
        for (int i = 0; i <= blob.Length - message.Length; i++)
        {
            if (!Match(blob, i, message))
                continue;
            bool printkPrefixed = i >= 2 && blob[i - 2] == 0x01;
            if (!printkPrefixed)
                throw new InvalidOperationException("anchor without printk level prefix; aborting");
            long stringStart = blobBase + i;
            return (stringStart + PhysToVirt) - 2;
        }
        throw new InvalidOperationException("anchor message not found in kernel rodata");
    }

    private static List<long> FindReferenceSites(int device, Range code, long reference)
    {
        byte[] blob = MapPhysicalRange(device, code, ProtRead, out long blobBase);
        var sites = FindMovwMovtPairs(blob, blobBase, reference);
        foreach (long site in sites)
        {
            int siteIndex = (int)(site - blobBase);
            uint movw = BitConverter.ToUInt32(blob, siteIndex);
            ushort imm = (ushort)((movw & 0xFFF) | ((movw >> 4) & 0xF000));
            if (((movw >> 20) & 0x3F) != 0x30 || imm != (ushort)(reference & 0xFFFF))
                throw new InvalidOperationException("reference site content mismatch; mapping inconsistent; aborting");
        }
        return sites;
    }

    private static List<long> FindZeroedGlobals(int device, Range code, Range data, long site)
    {
        byte[] blob = MapPhysicalRange(device, code, ProtRead, out long blobBase);
        int siteIndex = (int)(site - blobBase);
        long dataVirtBase = data.Start + PhysToVirt;
        long dataVirtEnd = data.End + PhysToVirt;
        var candidates = new List<long>();
        int functionStart = siteIndex;
        while (functionStart > 0 && BitConverter.ToUInt32(blob, functionStart) != PrologueMoveIpSp)
            functionStart -= 4;
        for (int offset = functionStart; offset < Math.Min(siteIndex + 0x100, blob.Length - 4); offset += 4)
        {
            uint store = BitConverter.ToUInt32(blob, offset);
            if ((store & 0xFFF00000) != 0xE5800000)
                continue;
            uint baseRegister = (store >> 16) & 0xF;
            uint sourceRegister = (store >> 12) & 0xF;
            long immediate = store & 0xFFF;
            if (!WritesConstantZero(blob, offset, sourceRegister))
                continue;
            long? baseAddress = ReadBaseRegisterAddress(blob, offset, baseRegister);
            if (baseAddress == null)
                continue;
            long target = baseAddress.Value + immediate;
            if (target >= dataVirtBase && target <= dataVirtEnd && (target & 3) == 0)
                candidates.Add(target - PhysToVirt);
        }
        return candidates;
    }

    private static uint[] ReadWords(int device, long physical, int count)
    {
        long page = physical & ~0xFFFL;
        IntPtr mapping = Mmap2(IntPtr.Zero, 4096, ProtRead, MapShared, device, (uint)(page >> 12));
        var blob = new byte[4096];
        Marshal.Copy(mapping, blob, 0, blob.Length);
        Munmap(mapping, 4096);
        int offsetInPage = (int)(physical - page);
        var words = new uint[count];
        for (int i = 0; i < count; i++)
            words[i] = BitConverter.ToUInt32(blob, offsetInPage + i * 4);
        return words;
    }

    private static int DisableUep(int device, long statusWord, bool disabled)
    {
        if (disabled)
        {
            Console.WriteLine("already disabled, nothing to do");
            return 0;
        }
        uint current = ReadWords(device, statusWord, 1)[0];
        SaveWord(current);
        WriteWords(device, statusWord, 0);
        VerifyWords(device, statusWord, 0);
        Console.WriteLine("UEP disabled via status word (RAM only, until reboot)");
        return 0;
    }

    private static int EnableUep(int device, long statusWord, bool disabled)
    {
        if (!disabled)
        {
            Console.WriteLine("not disabled, nothing to do");
            return 0;
        }
        uint original = LoadWord();
        WriteWords(device, statusWord, original);
        VerifyWords(device, statusWord, original);
        Console.WriteLine("UEP restored");
        return 0;
    }

    private static bool Match(byte[] blob, int at, byte[] needle)
    {
        for (int j = 0; j < needle.Length; j++)
            if (blob[at + j] != needle[j])
                return false;
        return true;
    }

    private static List<long> FindMovwMovtPairs(byte[] blob, long blobBase, long target)
    {
        var hits = new List<long>();
        ushort lowHalf = (ushort)(target & 0xFFFF);
        ushort highHalf = (ushort)((target >> 16) & 0xFFFF);
        for (int offset = 0; offset + 8 <= blob.Length; offset += 4)
        {
            uint movw = BitConverter.ToUInt32(blob, offset);
            if ((movw >> 28) != 0xE || ((movw >> 20) & 0x3F) != 0x30)
                continue;
            ushort imm16 = (ushort)((movw & 0xFFF) | ((movw >> 4) & 0xF000));
            if (imm16 != lowHalf)
                continue;
            uint register = (movw >> 12) & 0xF;
            for (int offset2 = offset; offset2 < offset + 40 && offset2 + 4 <= blob.Length; offset2 += 4)
            {
                uint movt = BitConverter.ToUInt32(blob, offset2);
                if ((movt >> 28) != 0xE || ((movt >> 20) & 0x3F) != 0x34)
                    continue;
                if (((movt >> 12) & 0xF) != register)
                    continue;
                if ((ushort)((movt & 0xFFF) | ((movt >> 4) & 0xF000)) == highHalf)
                    hits.Add(blobBase + offset);
                break;
            }
        }
        return hits.Distinct().ToList();
    }

    private static bool WritesConstantZero(byte[] blob, int storeOffset, uint sourceRegister)
    {
        for (int offset = storeOffset - 4; offset >= storeOffset - 48 && offset >= 0; offset -= 4)
        {
            uint word = BitConverter.ToUInt32(blob, offset);
            if ((word >> 28) != 0xE || ((word >> 12) & 0xF) != sourceRegister)
                continue;
            bool dataProcessing = ((word >> 26) & 3) == 0;
            bool load = ((word >> 26) & 3) == 1 && (word & (1 << 20)) != 0;
            if (!dataProcessing && !load)
                continue;
            return (word & 0xFFEF0FFF) == 0xE3A00000;
        }
        return false;
    }

    private static long? ReadBaseRegisterAddress(byte[] blob, int storeOffset, uint register)
    {
        ushort? highHalf = null;
        for (int offset = storeOffset - 4; offset >= storeOffset - 96 && offset >= 0; offset -= 4)
        {
            uint word = BitConverter.ToUInt32(blob, offset);
            if ((word >> 28) != 0xE)
                continue;
            uint opcode = (word >> 20) & 0x3F;
            if (opcode != 0x30 && opcode != 0x34)
            {
                if (((word >> 12) & 0xF) == register && ((word >> 26) & 3) <= 1)
                    return null;
                continue;
            }
            if (((word >> 12) & 0xF) != register)
                continue;
            ushort imm16 = (ushort)((word & 0xFFF) | ((word >> 4) & 0xF000));
            if (opcode == 0x34)
            {
                if (highHalf != null)
                    return null;
                highHalf = imm16;
                continue;
            }
            if (highHalf == null)
                return null;
            return ((long)highHalf.Value << 16) | imm16;
        }
        return null;
    }

    private static void SaveWord(uint value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(SavedValuePath));
        File.WriteAllBytes(SavedValuePath, BitConverter.GetBytes(value));
    }

    private static uint LoadWord()
    {
        if (!File.Exists(SavedValuePath))
            throw new InvalidOperationException("no saved value at " + SavedValuePath + "; cannot restore safely");
        return BitConverter.ToUInt32(File.ReadAllBytes(SavedValuePath), 0);
    }

    private static void WriteWords(int device, long physical, uint word)
    {
        long page = physical & ~0xFFFL;
        IntPtr mapping = Mmap2(IntPtr.Zero, 4096, ProtRead | ProtWrite, MapShared, device, (uint)(page >> 12));
        int offsetInPage = (int)(physical - page);
        Marshal.Copy(BitConverter.GetBytes(word), 0, new IntPtr(mapping.ToInt64() + offsetInPage), 4);
        Munmap(mapping, 4096);
    }

    private static void VerifyWords(int device, long physical, uint expected)
    {
        uint written = ReadWords(device, physical, 1)[0];
        bool ok = written == expected;
        Console.WriteLine("verify: read back 0x{0:x8} -> {1}", written, ok ? "OK" : "MISMATCH");
        if (!ok)
            throw new InvalidOperationException("read-back mismatch");
    }

    private static byte[] MapPhysicalRange(int device, Range range, int protection, out long mappedBase)
    {
        mappedBase = range.Start & ~0xFFF;
        long headSlop = range.Start - mappedBase;
        long size = range.End - range.Start + 1 + headSlop;
        IntPtr mapping = Mmap2(IntPtr.Zero, size, protection, MapShared, device, (uint)(mappedBase >> 12));
        byte[] blob = new byte[size];
        Marshal.Copy(mapping, blob, 0, (int)size);
        Munmap(mapping, size);
        return blob;
    }

    private sealed class Range
    {
        public long Start;
        public long End;
    }

    private const int OpenReadWrite = 2;

    private static int OpenDevice(string path, int flags)
    {
        int device = Open(path, flags);
        if (device < 0)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "open " + path + " failed");
        return device;
    }

    private static IntPtr Mmap2(IntPtr address, long length, int protection, int flags, int device, uint pageOffset)
    {
        IntPtr mapping = SyscallMmap2(SysMmap2Arm, address, new UIntPtr((ulong)length), protection, flags, device, pageOffset);
        if (mapping == new IntPtr(-1))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "mmap2 failed");
        return mapping;
    }

    private static void Munmap(IntPtr mapping, long length)
    {
        munmap(mapping, new UIntPtr((ulong)length));
    }

    [DllImport("libc", EntryPoint = "syscall", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    private static extern IntPtr SyscallMmap2(int number, IntPtr address, UIntPtr length, int protection, int flags, int fileDescriptor, uint pageOffset);

    [DllImport("libc", SetLastError = true)]
    private static extern int munmap(IntPtr address, UIntPtr length);

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int CloseDevice(int fileDescriptor);
}
