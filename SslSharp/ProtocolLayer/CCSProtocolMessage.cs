using System;
using System.Text;

namespace SslSharp.ProtocolLayer
{
    /* Change Cipher Spec Protocol Message */
    class CCSProtocolMessage : IProtocolMessage
    {
        public enum CCSType { ChangeCipherSpec = 1 };
        CCSType type;

        public CCSProtocolMessage(CCSType t)
        {
            type = t;
        }

        public CCSProtocolMessage(byte[] buffer)
        {
            type = (CCSType)(buffer[0]);
        }

        public byte[] GetBytes()
        {
            byte[] result = new byte[1];
            result[0] = (byte)((ushort)type & 0xff);
            return result;
        }

        public ushort GetLength()
        {
            return (ushort)1;
        }

        public new ProtoType GetType()
        {
            return ProtoType.ChangeCipherSpec;
        }


        public void Process(IProtocolHandler pHandler)
        {
            pHandler.ProcessChangeCipherSpecMessage();
        }
    }
}
