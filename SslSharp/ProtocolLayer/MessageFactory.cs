using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.Exceptions;

namespace SslSharp.ProtocolLayer
{
    class MessageFactory
    {
        public static ExtractMessagesResult ExtractMessages(ProtoType type, byte[] buffer)
        {
            ExtractMessagesResult result = new ExtractMessagesResult();

            switch (type)
            {
                case ProtoType.Handshake:
                    CreateHandshakeMessages(buffer, result);
                    break;

                case ProtoType.ChangeCipherSpec:
                    CCSProtocolMessage cMsg = CreateCCSMessage(buffer);
                    result.protocolMessages.Add(cMsg);
                    break;
                
                case ProtoType.Alert:
                    AlertProtocolMessage aMsg = CreateAlertMessage(buffer);
                    result.protocolMessages.Add(aMsg);
                    break;
                
                case ProtoType.ApplicationData:
                    ApplicationProtocolMessage apm = CreateAPMessage(buffer);
                    result.protocolMessages.Add(apm);
                    break;
            }

            return result;
        }

        public class ExtractMessagesResult
        {
            public List<IProtocolMessage> protocolMessages = new List<IProtocolMessage>();
            public List<HandshakeProtocolMessage> handshakeMessages = new List<HandshakeProtocolMessage>();
        }

        private static ApplicationProtocolMessage CreateAPMessage(byte[] buffer)
        {
            ApplicationProtocolMessage apm = new ApplicationProtocolMessage(buffer);
            return apm;
        }

        private static AlertProtocolMessage CreateAlertMessage(byte[] buffer)
        {
            AlertProtocolMessage aMsg = null;
            try
            {
                aMsg = new AlertProtocolMessage(buffer);
            }
            catch (Exception)
            {
                throw new SslAlertException(AlertLevel.Fatal, AlertDescription.DecodeError);
            }
            return aMsg;
        }

        private static CCSProtocolMessage CreateCCSMessage(byte[] buffer)
        {
            CCSProtocolMessage cMsg = null;
            try
            {
                cMsg = new CCSProtocolMessage(buffer);
            }
            catch (Exception)
            {
                throw new SslAlertException(AlertLevel.Fatal, AlertDescription.DecodeError);
            }
            return cMsg;
        }

        private static void CreateHandshakeMessages(byte[] buffer, ExtractMessagesResult result)
        {
            int startOffset = 0;
            int endOffset = startOffset + buffer.Length;

            
            while (startOffset < endOffset)
            {
                HandshakeDataType type = (HandshakeDataType)buffer[startOffset++]; 
                byte[] len = new byte[4];
                System.Buffer.BlockCopy(buffer, startOffset, len, 1, 3);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(len);
                int messageLength = (int)(BitConverter.ToUInt32(len, 0));
                startOffset += 3;
                byte[] message = new byte[messageLength];
                System.Buffer.BlockCopy(buffer, startOffset, message, 0, message.Length);
                startOffset += message.Length;
                HandshakeProtocolMessage hMsg = null;
                try
                {
                    hMsg = new HandshakeProtocolMessage(type, message);
                }
                catch (Exception)
                {
                    throw new SslAlertException(AlertLevel.Fatal, AlertDescription.DecodeError);
                }
                result.protocolMessages.Add(hMsg);
                if (type != HandshakeDataType.Finished)
                    result.handshakeMessages.Add(hMsg);
            }
        }
    }
}
