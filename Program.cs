using System;
using System.IO;
using System.Text;

class XpfTool
{
    struct XpfHeader
    {
        public string Magic;    // "XPF0"
        public uint DataOffset;
        public uint NumFiles;
        public byte[] Padding;  // 4 bytes
    }

    struct XpfEntry
    {
        public string Filename; 
        public uint Offset;     
        public uint Length;     
    }

    static string? g_CustomOutputFolderName = null;

    static void MakeDirIfFolder(string name)
    {
        int slash = name.IndexOf('/');
        if (slash <= 0) return;

        string dir = name.Substring(0, slash);
        string path = g_CustomOutputFolderName != null
            ? Path.Combine(g_CustomOutputFolderName, dir)
            : dir;

        if (!Directory.Exists(path))
            Directory.CreateDirectory(path);
    }

    static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine($"Usage: XpfTool <input.xpf> [output directory]");
            return 0;
        }

        string inputPath = args[0];
        g_CustomOutputFolderName = args.Length > 1 ? args[1] : null;

        if (g_CustomOutputFolderName != null && !Directory.Exists(g_CustomOutputFolderName))
            Directory.CreateDirectory(g_CustomOutputFolderName);

        using var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
        using var br = new BinaryReader(fs);

        // header
        XpfHeader hdr = new XpfHeader
        {
            Magic = Encoding.ASCII.GetString(br.ReadBytes(4)),
            DataOffset = br.ReadUInt32(),
            NumFiles = br.ReadUInt32(),
            Padding = br.ReadBytes(4)
        };

        if (!hdr.Magic.StartsWith("XPF"))
        {
            Console.WriteLine("Invalid XPF file.");
            return 0;
        }

        // entries
        XpfEntry[] entries = new XpfEntry[hdr.NumFiles];
        for (uint i = 0; i < hdr.NumFiles; i++)
        {
            byte[] nameBytes = br.ReadBytes(24);
            int nul = Array.IndexOf(nameBytes, (byte)0);
            string name = (nul >= 0 ? Encoding.ASCII.GetString(nameBytes, 0, nul) : Encoding.ASCII.GetString(nameBytes))
                          .Replace('\\', '/');
            uint off = br.ReadUInt32();
            uint len = br.ReadUInt32();
            entries[i] = new XpfEntry { Filename = name, Offset = off, Length = len };
        }

        long dataSz = 0;
        for (uint i = 0; i < hdr.NumFiles; i++) dataSz += entries[i].Length;
        byte[] data = br.ReadBytes((int)dataSz);

        for (uint i = 0; i < hdr.NumFiles; i++)
        {
            var e = entries[i];
            string outPath = g_CustomOutputFolderName != null
                ? Path.Combine(g_CustomOutputFolderName, e.Filename)
                : e.Filename;

            Console.WriteLine($"Extracting {e.Filename}...");
            MakeDirIfFolder(e.Filename);

            string? outDir = Path.GetDirectoryName(outPath);
            if (!string.IsNullOrEmpty(outDir) && !Directory.Exists(outDir))
                Directory.CreateDirectory(outDir);

            int entryStart = checked((int)e.Offset);
            if (entryStart < 0 || entryStart + 4 > data.Length)
                throw new InvalidDataException("Entry offset out of range");

            // NESTED-XPF CHECK
            if (e.Length >= 4 &&
                data[entryStart + 0] == (byte)'X' &&
                data[entryStart + 1] == (byte)'P' &&
                data[entryStart + 2] == (byte)'F')
            {
                int available = data.Length - entryStart;
                int toWrite = (int)Math.Min(e.Length, available);

                using (var bw = new BinaryWriter(File.Open(outPath, FileMode.Create, FileAccess.Write)))
                {
                    bw.Write(data, entryStart, toWrite);
                }
                Console.WriteLine($" -> wrote nested XPF (raw, {toWrite} bytes)");
                continue;
            }

            // otherwise: decompress
            uint beSize = (uint)(
                (data[entryStart + 0] << 24) |
                (data[entryStart + 1] << 16) |
                (data[entryStart + 2] << 8) |
                (data[entryStart + 3] << 0)
            );
            int decSz = unchecked((int)beSize);

            byte[] buffer = new byte[decSz];
            Decompress(buffer, data, entryStart);

            using (var bw = new BinaryWriter(File.Open(outPath, FileMode.Create, FileAccess.Write)))
            {
                bw.Write(buffer, 0, decSz);
            }
            Console.WriteLine($" -> decompressed {decSz} bytes");
        }

        Console.WriteLine("\nDone!");
        return 0;
    }
    static int Decompress(byte[] outBuf, byte[] inBuf, int inPos)
    {
        int decSz;
        int outPos = 0;

        // original weird size calc
        int first4 = BitConverter.ToInt32(inBuf, inPos);
        decSz = (first4 >> 8);
        decSz = (decSz >> 16) | (decSz & 0xff00) | ((decSz & 0xff) << 16);

        int flag = inBuf[inPos + 4] & 0xFF;
        int dataPos = inPos + 5;
        int maskA = 0x80;

        int maskB, unk, copyLen, distance;

        while (true)
        {
            // literals
            while (true)
            {
                maskB = maskA;
                unk = flag & maskA;

                if (maskA == 0)
                {
                    if (dataPos >= inBuf.Length) return decSz;
                    flag = inBuf[dataPos++] & 0xFF;
                    maskB = 0x80;
                    unk = flag & 0x80;
                }

                maskB >>= 1;
                maskA = maskB;

                if (unk != 0) break;

                if (dataPos >= inBuf.Length || outPos >= outBuf.Length) return decSz;
                outBuf[outPos++] = inBuf[dataPos++];
            }

            unk = flag & maskA;
            if (maskA == 0)
            {
                if (dataPos >= inBuf.Length) return decSz;
                flag = inBuf[dataPos++] & 0xFF;
                maskB = 0x80;
                unk = flag & 0x80;
            }

            int ch = (dataPos < inBuf.Length) ? (inBuf[dataPos] & 0xFF) : 0;

            if (unk == 0)
            {
                if (ch == 0) return decSz;

                distance = (inBuf[dataPos] | unchecked((int)0xFFFFFF00));
                dataPos++;
            }
            else
            {
                maskA = maskB >> 1;
                int next = dataPos + 1;

                if (maskA == 0)
                {
                    if (next >= inBuf.Length) return decSz;
                    flag = inBuf[next] & 0xFF;
                    maskA = 0x80;
                    next = dataPos + 2;
                }

                copyLen = (ch | unchecked((int)0xFFFFFF00)) << 1;
                if ((flag & maskA) != 0) copyLen++;

                maskB = maskA >> 1;
                maskA = flag & maskB;

                if (maskB == 0)
                {
                    if (next >= inBuf.Length) return decSz;
                    flag = inBuf[next++] & 0xFF;
                    maskB = 0x80;
                    maskA = flag & 0x80;
                }

                copyLen <<= 1;
                if (maskA != 0) copyLen++;

                maskB >>= 1;
                maskA = flag & maskB;
                if (maskB == 0)
                {
                    if (next >= inBuf.Length) return decSz;
                    flag = inBuf[next++] & 0xFF;
                    maskB = 0x80;
                    maskA = flag & 0x80;
                }

                copyLen <<= 1;
                if (maskA != 0) copyLen++;

                maskB >>= 1;
                maskA = flag & maskB;
                if (maskB == 0)
                {
                    if (next >= inBuf.Length) return decSz;
                    flag = inBuf[next++] & 0xFF;
                    maskB = 0x80;
                    maskA = flag & 0x80;
                }

                copyLen <<= 1;
                if (maskA != 0) copyLen++;

                distance = copyLen - 0xFF;
                dataPos = next;
            }

            copyLen = 1;
            while (true)
            {
                maskB >>= 1;
                maskA = flag & maskB;
                if (maskB == 0)
                {
                    if (dataPos >= inBuf.Length) return decSz;
                    flag = inBuf[dataPos++] & 0xFF;
                    maskB = 0x80;
                    maskA = flag & 0x80;
                }

                maskB >>= 1;
                if (maskA == 0) break;

                maskA = flag & maskB;
                if (maskB == 0)
                {
                    if (dataPos >= inBuf.Length) return decSz;
                    flag = inBuf[dataPos++] & 0xFF;
                    maskB = 0x80;
                    maskA = flag & 0x80;
                }

                copyLen <<= 1;
                if (maskA != 0) copyLen++;
            }

            maskA = maskB;

            while (copyLen-- > -1)
            {
                int refPos = outPos + distance;
                if (refPos < 0 || refPos >= outPos) return decSz;
                if (outPos >= outBuf.Length) return decSz;
                outBuf[outPos++] = outBuf[refPos];
            }
        }
    }
}
