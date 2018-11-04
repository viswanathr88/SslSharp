using System;
using System.Text;

namespace SslSharp.ProtocolLayer
{
    public enum HandshakeDataType
    {
        HelloRequest = 0,
        ClientHello = 1,
        ServerHello = 2,
        Certificate = 11,
        ServerKeyExchange = 12,
        CertificateRequest = 13,
        ServerHelloDone = 14,
        CertificateVerify = 15,
        ClientKeyExchange = 16,
        Finished = 20
    };

    public interface IHandshakeData
    {
        byte[] GetBytes();

        /* properties */
        UInt32 GetLength();
        HandshakeDataType GetType();

        void Process(IProtocolHandler pHandler);
    }
}
