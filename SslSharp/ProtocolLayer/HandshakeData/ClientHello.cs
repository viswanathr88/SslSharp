using System;
using System.Text;

using SslSharp.Collections;


using SslSharp.Shared;

namespace SslSharp.ProtocolLayer
{
    public class ClientHello : IHandshakeData
    {
        ProtocolVersion version = null;
        RandomUnit random = null;
        SessionID sid = null;
        byte[] clientRandom = null;

        /* constructor */
        public ClientHello()
        {
            version = new ProtocolVersion();
            random = new RandomUnit();
            sid = new SessionID(0, 0);
            clientRandom = random.GetBytes();
        }

        /* utility methods */
        public byte[] GetBytes()
        {
            byte[] result = new byte[this.GetLength()];
            int offset = 0;

            System.Buffer.BlockCopy(version.GetBytes(), 0, result, offset, version.Length);
            offset += version.Length;

            System.Buffer.BlockCopy(random.GetBytes(), 0, result, offset, RandomUnit.Length);
            offset += RandomUnit.Length;

            System.Buffer.BlockCopy(sid.ToBytes(), 0, result, offset, sid.Length == 0 ? 1 : 0);
            offset += sid.Length == 0 ? 1 : 0;

            byte[] length = BitConverter.GetBytes((ushort)(2 * CipherSuites.Length));
            if (BitConverter.IsLittleEndian)
                Array.Reverse(length);

            System.Buffer.BlockCopy(length, 0, result, offset, 2);
            offset += 2;

            System.Buffer.BlockCopy(CipherSuites.GetSupportedSuitesInBytes(), 0, result, offset, (CipherSuites.Length * 2));
            offset += CipherSuites.Length * 2;

            System.Buffer.BlockCopy(CompressionList.ToBytes(), 0, result, offset, 1 + CompressionList.Length);
            offset += 1 + CompressionList.Length;

            return result;
        }


        public UInt32 GetLength()
        {
            return (uint)(version.Length + RandomUnit.Length + 1 + sid.Length +
                    2 + (2 * CipherSuites.Length) + 1 + CompressionList.Length);
        }

        public new HandshakeDataType GetType()
        {
            return HandshakeDataType.ClientHello;
        }

        internal byte[] GetClientRandom()
        {
            return clientRandom;
        }

        internal ProtocolVersion GetClientVersion()
        {
            return version;
        }


        public void Process(IProtocolHandler pHandler)
        {
            return;
        }
    }
}
