using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.Shared;
using System.Security.Cryptography.X509Certificates;

namespace SslSharp.ProtocolLayer
{
    public interface IProtocolHandler
    {
        void ProcessHandshakeMessage(IHandshakeData hData);
        void ProcessAlertMessage(AlertLevel level, AlertDescription desc);
        void ProcessChangeCipherSpecMessage();
        void ProcessApplicationMessage(byte[] data);

        void ProcessServerHello(SessionID sid,
            byte[] serverRandom, ProtocolVersion serverVersion,
            TlsCipherSuite chosenSuite, TlsCompressionMethod chosenCompMethod);

        void ProcessCertificate(List<X509Certificate> lCertificates);

        void ProcessServerHelloDone();

        void ProcessFinished(byte[] payload);

        void ProcessHelloRequest();
    }
}
