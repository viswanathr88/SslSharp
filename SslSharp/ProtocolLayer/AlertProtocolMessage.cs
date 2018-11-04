using System;
using System.Text;

using SslSharp.RecordLayer;

namespace SslSharp.ProtocolLayer
{
    public enum AlertLevel { Warning = 1, Fatal = 2 };

    public enum AlertDescription
    {
        CloseNotify = 0,
        UnexpectedMessage = 10,
        BadRecordMac = 20,
        DecryptionFailedReserved = 21,
        RecordOverflow = 22,
        DecompressionFailure = 30,
        HandshakeFailure = 40,
        NoCertificateReserved = 41,
        BadCertificate = 42,
        UnsupportedCertificate = 43,
        CertificateRevoked = 44,
        CertificateExpired = 45,
        CertificateUnknown = 46,
        IllegalParameter = 47,
        UnknownCa = 48,
        AccessDenied = 49,
        DecodeError = 50,
        DecryptError = 51,
        ExportRestrictionReserved = 60,
        ProtocolVersion = 70,
        InsufficientSecurity = 71,
        InternalError = 80,
        UserCancelled = 90,
        NoRenegotiation = 100,
        UnsupportedExtension = 110
    };

    public class AlertProtocolMessage : IProtocolMessage
    {

        AlertLevel level;
        AlertDescription desc;
        
        /* Length of this message is 2 bytes */

        public AlertProtocolMessage(AlertLevel l, AlertDescription d)
        {
            level = l;
            desc = d;
        }

        public AlertProtocolMessage(byte[] buffer)
        {
            level = (AlertLevel)(buffer[0]);
            desc = (AlertDescription)(buffer[1]);
        }

        public AlertLevel Level
        {
            get { return level; }
        }

        public AlertDescription Description
        {
            get { return desc; }
        }

        public byte[] GetBytes()
        {
            byte[] result = new byte[2];
            result[0] = (byte)((ushort)level & 0xff);
            result[1] = (byte)((ushort)desc & 0xff);
            return result;
        }

        public ushort GetLength()
        {
            return (ushort)2;
        }

        public new ProtoType GetType()
        {
            return ProtoType.Alert;
        }


        public void Process(IProtocolHandler pHandler)
        {
            pHandler.ProcessAlertMessage(level, desc);
        }
    }
}
