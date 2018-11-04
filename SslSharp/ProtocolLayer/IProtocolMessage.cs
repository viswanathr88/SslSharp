using System;
using System.Text;

namespace SslSharp.ProtocolLayer
{
    public interface IProtocolMessage
    {
        byte[] GetBytes();
        UInt16 GetLength();
        ProtoType GetType();

        void Process(IProtocolHandler pHandler);
    }
}
