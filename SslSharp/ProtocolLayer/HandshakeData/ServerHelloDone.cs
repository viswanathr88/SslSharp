using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.Collections;
using SslSharp.RecordLayer;

namespace SslSharp.ProtocolLayer
{
    class ServerHelloDone : IHandshakeData
    {
        public ServerHelloDone(byte[] buffer)
        {
            
        }

        public byte[] GetBytes()
        {
            return null;
        }

        public uint GetLength()
        {
            return 0;
        }

        public new HandshakeDataType GetType()
        {
            return HandshakeDataType.ServerHelloDone;
        }


        public void Process(IProtocolHandler pHandler)
        {
            pHandler.ProcessServerHelloDone();
        }
    }
}
