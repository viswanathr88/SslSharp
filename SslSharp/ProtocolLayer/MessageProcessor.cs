using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using SslSharp.Shared;
using SslSharp.Exceptions;
using SslSharp.Collections;
using Kishore.X509.Parser;
using SslSharp.Security.Cryptography;

namespace SslSharp.ProtocolLayer
{
    /// <summary>
    /// Handles all protocols above the record layer
    /// </summary>
    public delegate void ParametersReadyDelegate(SecurityParameters param);
    public delegate void ChangeCipherSpecReceivedDelegate();

    partial class MessageProcessor : IProtocolHandler
    {
        List<HandshakeProtocolMessage> m_ListOfHandshakeMsgs;
        SecurityParameters m_SecurityParameters = null;
        Queue<IProtocolMessage> m_ProtocolQueue;
        Session m_Session = null;
        HandshakeDataType m_HandshakePhase;
        MessageFactory m_MessageFactory;


        public event ParametersReadyDelegate ParametersReady;
        public event ChangeCipherSpecReceivedDelegate ChangeCipherSpecReceived;

        /// <summary>
        /// Creates a new instance of Protocol Manager

        /// </summary>
        internal MessageProcessor()
        {
            m_ProtocolQueue = new Queue<IProtocolMessage>();
            m_Session = new Session();
            m_SecurityParameters = new SecurityParameters();
            m_MessageFactory = new MessageFactory();
            m_ListOfHandshakeMsgs = new List<HandshakeProtocolMessage>();
        }

        public List<IProtocolMessage> ProcessIncomingData(MessageFactory.ExtractMessagesResult result)
        {
            m_ListOfHandshakeMsgs.AddRange(result.handshakeMessages);
            foreach (IProtocolMessage message in result.protocolMessages)
            {
                message.Process(this);
            }

            List<IProtocolMessage> messages = new List<IProtocolMessage>();
            while (m_ProtocolQueue.Count != 0)
            {
                IProtocolMessage message = m_ProtocolQueue.Dequeue();
                messages.Add(message);
            }
            return messages;
        }

        public void ProcessAlertMessage(AlertLevel level, AlertDescription desc)
        {
            if (level == AlertLevel.Fatal)
                throw new SslFatalAlertReceived();
        }

        public IProtocolMessage CreateAlertMessage(AlertLevel level, AlertDescription desc)
        {
            AlertProtocolMessage apm = new AlertProtocolMessage(level, desc);
            return apm;
        }

        public void ProcessApplicationMessage(byte[] data)
        {
            m_ProtocolQueue.Enqueue(new ApplicationProtocolMessage(data));
        }

        public void ProcessHandshakeMessage(IHandshakeData hData)
        {
            hData.Process(this);
        }

        internal IProtocolMessage CreateClientHello()
        {
            ClientHello chm = new ClientHello();
            m_SecurityParameters.ClientRandom = chm.GetClientRandom();
            m_SecurityParameters.ChosenVersion = chm.GetClientVersion();
            HandshakeProtocolMessage hpm = new HandshakeProtocolMessage(chm);
            m_ListOfHandshakeMsgs.Add(hpm);
            m_HandshakePhase = HandshakeDataType.ClientHello;
            return hpm;
        }

        public void ProcessServerHello(SessionID sid,
            byte[] serverRandom, ProtocolVersion serverVersion,
            TlsCipherSuite chosenSuite, TlsCompressionMethod chosenCompMethod)
        {
            if (m_HandshakePhase != HandshakeDataType.ClientHello)
                throw new SslAlertException(AlertLevel.Fatal, AlertDescription.UnexpectedMessage);

            m_Session.Id = sid;
            m_Session.CompressionMethod = chosenCompMethod;
            m_Session.IsResumable = false;

            if (CipherSuites.IsSupported(chosenSuite))
            {
                m_Session.CipherSuite = chosenSuite;
                m_SecurityParameters.CipherSuite = chosenSuite;
            }
            else
                throw new SslAlertException(AlertLevel.Fatal, AlertDescription.HandshakeFailure);

            /* TODO: Check for wrong version */
            if (serverVersion.Major != 3 || serverVersion.Minor != 1)
            {
                throw new SslAlertException(AlertLevel.Fatal, AlertDescription.HandshakeFailure);
            }

            m_SecurityParameters.ServerRandom = serverRandom;
            m_HandshakePhase = HandshakeDataType.ServerHello;
        }

        public void ProcessCertificate(List<X509Certificate> lCertificates)
        {
            if (m_HandshakePhase != HandshakeDataType.ServerHello)
                throw new SslAlertException(AlertLevel.Fatal, AlertDescription.UnexpectedMessage);
            m_Session.Certificate = lCertificates[0];

            m_HandshakePhase = HandshakeDataType.Certificate;

            /* TODO: Verify Cert */
        }

        public void ProcessServerHelloDone()
        {
            m_HandshakePhase = HandshakeDataType.ServerHelloDone;
            PreMasterSecret pms = new PreMasterSecret();
            byte[] keyExchangeData = GenerateKeyExchangeData(pms.GetBytes());

            /* Generate Master Secret */
            PrfDeriveBytes prf = new PrfDeriveBytes(pms.GetBytes(),
                "master secret",
                ByteArray.Concat(m_SecurityParameters.ClientRandom,
                m_SecurityParameters.ServerRandom));

            m_Session.MasterSecret = prf.GetBytes(48);
            m_SecurityParameters.MasterSecret = m_Session.MasterSecret;
            prf.Dispose();

            /* clear pre-master secret from memory */
            pms.Dispose();

            /* Create handshake messages */
            m_ProtocolQueue.Enqueue(CreateClientKeyExchange(keyExchangeData));
            m_ProtocolQueue.Enqueue(CreateChangeCipherSpec());
            m_ProtocolQueue.Enqueue(CreateFinishedMsg(m_SecurityParameters.MasterSecret));

            ParametersReady(m_SecurityParameters);
        }

        internal IProtocolMessage CreateClientKeyExchange(byte[] encryptedData)
        {
            if (m_HandshakePhase != HandshakeDataType.ServerHelloDone)
                throw new SslAlertException(AlertLevel.Fatal, AlertDescription.HandshakeFailure);
            HandshakeProtocolMessage hpm = new HandshakeProtocolMessage(new ClientKeyExchange(encryptedData));
            m_ListOfHandshakeMsgs.Add(hpm);
            m_HandshakePhase = HandshakeDataType.ClientKeyExchange;
            return hpm;
        }

        internal IProtocolMessage CreateFinishedMsg(byte[] masterSecret)
        {
            byte[] data = GetAllHandshakeInBytes();

            byte[] md5data = (new MD5Managed()).ComputeHash(data);
            byte[] sha1data = (new SHA1Managed()).ComputeHash(data);

            PrfDeriveBytes prf = new PrfDeriveBytes(masterSecret,
                "client finished", ByteArray.Concat(md5data, sha1data));

            byte[] result = prf.GetBytes(12);

            prf.Dispose();

            HandshakeProtocolMessage hpm = new HandshakeProtocolMessage(new Finished(result));
            m_ListOfHandshakeMsgs.Add(hpm);
            m_HandshakePhase = HandshakeDataType.Finished;
            return hpm;
        }

        public void ProcessFinished(byte[] payload)
        {
            if (m_HandshakePhase != HandshakeDataType.Finished)
                throw new SslAlertException(AlertLevel.Fatal, AlertDescription.UnexpectedMessage);

            byte[] data = GetAllHandshakeInBytes();

            byte[] sha1data = (new SHA1Managed()).ComputeHash(data);
            byte[] md5data = (new MD5Managed()).ComputeHash(data);

            PrfDeriveBytes prf = new PrfDeriveBytes(m_SecurityParameters.MasterSecret,
                "server finished", ByteArray.Concat(md5data, sha1data));

            byte[] result = prf.GetBytes(12);

            prf.Dispose();

            if (!ByteArray.AreEqual(result, payload))
                throw new SslAlertException(AlertLevel.Fatal, AlertDescription.DecryptError);
            else
            {
                /* Clear out list of handshake messages */
                m_ListOfHandshakeMsgs.Clear();
                throw new SslHandshakeCompleteException();
            }
        }

        public void ProcessHelloRequest()
        {
            AlertProtocolMessage apm = new AlertProtocolMessage(AlertLevel.Warning, AlertDescription.NoRenegotiation);
            m_ProtocolQueue.Enqueue(apm);
        }

        internal byte[] GetAllHandshakeInBytes()
        {
            byte[] result = null;
            for (int i = 0; i < m_ListOfHandshakeMsgs.Count; i++)
            {
                result = ByteArray.Concat(result, m_ListOfHandshakeMsgs[i].GetBytes());
            }
            return result;
        }

        internal byte[] GenerateKeyExchangeData(byte[] pms)
        {
            byte[] finalKeyExchangeData = null;

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            try
            {
                rsa.ImportParameters(X509PublicKeyParser.GetRSAPublicKeyParameters(m_Session.Certificate));
            }
            catch (Exception)
            {
                throw new SslAlertException(AlertLevel.Fatal, AlertDescription.BadCertificate);
            }

            RSAPKCS1KeyExchangeFormatter fmt = new RSAPKCS1KeyExchangeFormatter(rsa);
            byte[] keyExchangeData = fmt.CreateKeyExchange(pms);

            byte[] len = BitConverter.GetBytes((ushort)keyExchangeData.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(len);

            finalKeyExchangeData = ByteArray.Concat(len, keyExchangeData);
            return finalKeyExchangeData;
        }

        public void ProcessChangeCipherSpecMessage()
        {
            if (m_HandshakePhase != HandshakeDataType.Finished)
                throw new SslAlertException(AlertLevel.Fatal, AlertDescription.UnexpectedMessage);

            ChangeCipherSpecReceived();
        }

        internal IProtocolMessage CreateChangeCipherSpec()
        {
            if (m_HandshakePhase != HandshakeDataType.ClientKeyExchange)
                throw new SslAlertException(AlertLevel.Fatal, AlertDescription.HandshakeFailure);
            return new CCSProtocolMessage(CCSProtocolMessage.CCSType.ChangeCipherSpec);
        }
    }
}