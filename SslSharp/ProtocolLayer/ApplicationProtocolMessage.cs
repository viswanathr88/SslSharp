using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SslSharp.ProtocolLayer
{
    class ApplicationProtocolMessage : IProtocolMessage
    {
        byte[] m_Payload;

        public ApplicationProtocolMessage(byte[] payload)
        {
            m_Payload = payload;
        }
        public byte[] GetBytes()
        {
           return m_Payload;
        }

        public ushort GetLength()
        {
            return (ushort)m_Payload.Length;
        }

        public new ProtoType GetType()
        {
            return ProtoType.ApplicationData;
        }

        public void Process(IProtocolHandler pHandler)
        {
            pHandler.ProcessApplicationMessage(m_Payload);
        }
    }
}
