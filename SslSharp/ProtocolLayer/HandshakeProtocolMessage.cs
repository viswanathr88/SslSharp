using System;
using System.Text;
using System.Net.Sockets;
using System.IO;

namespace SslSharp.ProtocolLayer
{
    public class HandshakeProtocolMessage : IProtocolMessage
    {
        IHandshakeData hData;

        byte[] msgInBytes = null;

        /* constructor */
        public HandshakeProtocolMessage(IHandshakeData data)
        {
            this.hData = data;
        }

        public HandshakeProtocolMessage(HandshakeDataType type, byte[] buffer)
        {
            hData = HandshakeMessageFactory.FromBytes(type, buffer);
        }

        /* utility method */
        public byte[] GetBytes()
        {
            byte[] result = new byte[4 + hData.GetLength()];
            result[0] = (byte)((int)(hData.GetType()) & 0xff);
            byte[] len = BitConverter.GetBytes(hData.GetLength());
            if (BitConverter.IsLittleEndian)
                Array.Reverse(len);
            System.Buffer.BlockCopy(len, 1, result, 1, 3);

            byte[] payload = hData.GetBytes();
            if (payload != null)
                System.Buffer.BlockCopy(payload, 0, result, 4, payload.Length);

            if (msgInBytes == null)
            {
                msgInBytes = new byte[result.Length];
                System.Buffer.BlockCopy(result, 0, msgInBytes, 0, msgInBytes.Length);
            }
            return result;
        }
        public ushort GetLength()
        {
            return (ushort)(4 + hData.GetLength());
        }

        public new ProtoType GetType()
        {
            return ProtoType.Handshake;
        }

        public IHandshakeData GetHandshakeData()
        {
            return hData;
        }


        public void Process(IProtocolHandler pHandler)
        {
            pHandler.ProcessHandshakeMessage(hData);
        }
    }
}
