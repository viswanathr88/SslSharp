using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

using SslSharp.Collections;
using SslSharp.Exceptions;
using SslSharp.Shared;
using SslSharp.ProtocolLayer;

namespace SslSharp.RecordLayer
{
    class MessageAdapter
    {
        // 2 ^ 14 is the maximum payload size
        const int MAX_PAYLOAD_SIZE = 16384;
        private States m_States;

        ProtocolVersion chosenVersion = null;

        public MessageAdapter()
        {
            m_States = new States();
            chosenVersion = new ProtocolVersion();
        }

        public MessageFactory.ExtractMessagesResult FromRecord(Record record)
        {
            byte[] buffer = record.Payload;

            if (buffer.Length + 5 > MAX_PAYLOAD_SIZE + 2048)
                throw new SslAlertException(ProtocolLayer.AlertLevel.Fatal, ProtocolLayer.AlertDescription.RecordOverflow);

            State state = m_States.ActiveReadState;

            buffer = Decryptor.DecryptData(buffer, state);
            buffer = Deauthenticator.DeauthenticateData(buffer, record, state);
            buffer = Decompressor.DecompressData(buffer, state);

            return MessageFactory.ExtractMessages(record.Type, buffer);
        }

        public List<Record> ToRecords(IProtocolMessage message)
        {
            State state = m_States.ActiveWriteState;
            List<Record> listOfRecords = Fragmenter.FragmentData(message, chosenVersion, state);
            listOfRecords = Compressor.CompressData(listOfRecords, state);
            listOfRecords = Authenticator.AuthenticateData(listOfRecords, state);
            listOfRecords = Encryptor.EncryptData(listOfRecords, state);

            if (message.GetType() == ProtoType.ChangeCipherSpec)
                m_States.MakePendingWriteStateActive();

            return listOfRecords;
        }

        public void GrabSecurityParameters(SecurityParameters sParams)
        {
            CipherSuite cs = new CipherSuite(sParams.CipherSuite,
                sParams.MasterSecret, sParams.ClientRandom, sParams.ServerRandom);

            m_States.FillPendingStates(sParams.ChosenVersion, sParams.CompressionMethod, cs.Encryptor, cs.Decryptor,
                cs.ClientHasher, cs.ServerHasher);
        }

        public void ChangeCipherSpecRecd()
        {
            m_States.MakePendingReadStateActive();
        }
    }
}