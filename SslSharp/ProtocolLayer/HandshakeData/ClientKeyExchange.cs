using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Security.Cryptography;

namespace SslSharp.ProtocolLayer
{
    class ClientKeyExchange : IHandshakeData
    {
        byte[] payload = null;

        public ClientKeyExchange(byte[] pmsData)
        {
            this.payload = pmsData;
        }

        public byte[] GetBytes()
        {
            byte[] result = new byte[payload.Length + 2];
            byte[] len = BitConverter.GetBytes((ushort)payload.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(len);
            System.Buffer.BlockCopy(len, 0, result, 0, len.Length);
            System.Buffer.BlockCopy(payload, 0, result, 2, payload.Length);

            return payload;
        }

        public uint GetLength()
        {
            return (uint)payload.Length;
        }

        public new HandshakeDataType GetType()
        {
            return HandshakeDataType.ClientKeyExchange;
        }


        public void Process(IProtocolHandler pHandler)
        {
            return;
        }
    }
}
