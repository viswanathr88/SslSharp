using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.Collections;

namespace SslSharp.ProtocolLayer
{
    public enum ExtensionType : ushort
    {
        ServerName = 0x0000,
        RenegotiationInfo = 0xff01
    }
    class Extension
    {
        ExtensionType type;
        byte[] data;

        public Extension(ExtensionType type, byte[] data)
        {
            this.type = type;
            this.data = data;
        }

        public byte[] GetBytes()
        {
            byte[] typeBytes = BitConverter.GetBytes((ushort)type);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(typeBytes);
            byte[] length = BitConverter.GetBytes(data.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(length);
            return ByteArray.Concat(typeBytes, ByteArray.Concat(length, data));
        }

        public int GetLength()
        {
            return 4 + data.Length;
        }
    }
}