using System;
using System.Text;
using System.IO;

using SslSharp.ProtocolLayer;
using SslSharp.Collections;
using SslSharp.Shared;

namespace SslSharp.RecordLayer
{
    public class Record
    {
        ProtoType type;
        ProtocolVersion version = null;
        byte[] fragment;

        public Record(byte[] fragment, ProtoType type, ProtocolVersion chosenVersion)
        {
            this.type = type;
            this.fragment = fragment;
            this.version = chosenVersion;
        }

        public byte[] Payload
        {
            get { return fragment; }
            set { this.fragment = value; }
        }

        public byte[] GetBytes()
        {
            ushort length = (ushort)fragment.Length;
            byte[] result = new byte[length + 5];
            int offset = 0;
            System.Buffer.BlockCopy(BitConverter.GetBytes((char)(type)), 0, result, offset, 1);
            offset += 1;
            System.Buffer.BlockCopy(version.GetBytes(), 0, result, offset, version.Length);
            offset += version.Length;
            byte[] len = BitConverter.GetBytes(length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(len);

            System.Buffer.BlockCopy(len, 0, result, offset, len.Length);
            offset += len.Length;

            System.Buffer.BlockCopy(fragment, 0, result, offset, fragment.Length);
            offset += fragment.Length;

            return result;
        }

        /* properties */
        public ProtoType Type { get { return this.type; } }
        public ushort Length { get { return (ushort)(fragment.Length + 5); } }
        public ProtocolVersion Version { get { return this.version; } }
    }
}
