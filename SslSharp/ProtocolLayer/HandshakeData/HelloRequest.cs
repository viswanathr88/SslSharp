using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SslSharp.ProtocolLayer
{
    class HelloRequest : IHandshakeData
    {
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
            return HandshakeDataType.HelloRequest;
        }

        public void Process(IProtocolHandler pHandler)
        {
            pHandler.ProcessHelloRequest();
        }
    }
}
