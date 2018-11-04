using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.Collections;
using SslSharp.Shared;
using SslSharp.Exceptions;

namespace SslSharp.ProtocolLayer
{
    
    class ServerHello : IHandshakeData
    {
        ProtocolVersion version = null;
        SessionID sid = null;
        TlsCipherSuite chosenCipherSuite;
        TlsCompressionMethod chosenCompressionMethod;
        byte[] serverRandom = null;
        int messageLength = 0;

        byte[] data;

        public ServerHello(byte[] buffer)
        {
            messageLength = buffer.Length;
            if (data == null)
            {
                data = new byte[messageLength];
                Array.Copy(buffer, data, messageLength);
            }

            int offset = 0;
            int length = buffer.Length;

            version = new ProtocolVersion(buffer, offset);
            offset += version.Length;
            length -= version.Length;

            serverRandom = new byte[RandomUnit.Length];
            System.Buffer.BlockCopy(buffer, offset, serverRandom, 0, serverRandom.Length);
            offset += RandomUnit.Length;
            length -= RandomUnit.Length;

            /* Increment 1 byte for length and rt.Data[offset] bytes for size of sid */
            int sidLength = (ushort)(buffer[offset]);
            if (sidLength != 0)
                sid = new SessionID(buffer, offset + 1, (ushort)(buffer[offset]));
            offset += sidLength + 1;
            length -= (sidLength + 1);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(buffer, offset, 2);
            chosenCipherSuite = (TlsCipherSuite)BitConverter.ToUInt16(buffer, offset);
            offset += 2;
            length -= 2;

            chosenCompressionMethod = (TlsCompressionMethod)buffer[offset];
            offset += 1;
            length -= 1;

            //TODO: Check for extensions
            offset += length;

        }

        public byte[] GetBytes()
        {
            return data;
        }

        public uint GetLength()
        {
            return (uint)(messageLength);
        }

        public new HandshakeDataType GetType()
        {
            return HandshakeDataType.ServerHello;
        }

        public void Process(IProtocolHandler pHandler)
        {
            pHandler.ProcessServerHello(sid, serverRandom, version, chosenCipherSuite, chosenCompressionMethod);
        }
    }
}
