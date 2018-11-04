using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

using SslSharp.Collections;
using SslSharp.ProtocolLayer;
using SslSharp.RecordLayer;
using SslSharp.Exceptions;

namespace SslSharp
{
    class Bus
    {
        const int MAX_BUFFER_SIZE = 18000;

        private byte[] m_Buffer = null;

        MessageAdapter m_MessageAdapter;
        RecordAdapter m_RecordAdapter;

        ByteQueue m_InputQueue;

        MessageProcessor m_ProtocolLayer;
        QueueHandler m_QHandler;

        /// <summary>
        /// Creates an instance of Bus that handles communication between the layers
        /// </summary>
        public Bus()
        {
            m_MessageAdapter = new MessageAdapter();
            m_RecordAdapter = new RecordAdapter();

            m_InputQueue = new ByteQueue();

            m_ProtocolLayer = new ProtocolLayer.MessageProcessor();
            m_QHandler = new QueueHandler();

            /* Create the buffer once - reuse later */
            m_Buffer = new byte[MAX_BUFFER_SIZE];

            m_ProtocolLayer.ParametersReady += new ParametersReadyDelegate(m_MessageAdapter.GrabSecurityParameters);
            m_ProtocolLayer.ChangeCipherSpecReceived += new ChangeCipherSpecReceivedDelegate(m_MessageAdapter.ChangeCipherSpecRecd);
        }
        /// <summary>
        /// Starts the handshake process
        /// </summary>
        /// <returns>Returns the handshake data as a byte stream to be sent to the remote host</returns>
        internal List<Record> StartHandshake()
        {
            IProtocolMessage message = m_ProtocolLayer.CreateClientHello();
            return m_MessageAdapter.ToRecords(message);
        }

        internal void HandleReceivedData(byte[] data, int offset, int length)
        {
            byte[] requiredData = new byte[length];
            System.Buffer.BlockCopy(data, offset, requiredData, 0, length);

            Record record = null;

            m_InputQueue.Enqueue(requiredData);

            while ((record = m_RecordAdapter.FromByteQueue(m_InputQueue)) != null)
            {
                if (!Enum.IsDefined(typeof(ProtoType), record.Type))
                {
                    Console.WriteLine("Unknown record. Ignoring");
                    continue;
                }
                MessageFactory.ExtractMessagesResult result = m_MessageAdapter.FromRecord(record);
                List<IProtocolMessage> outputMessages = m_ProtocolLayer.ProcessIncomingData(result);

                foreach (IProtocolMessage message in outputMessages)
                {
                    if (message.GetType() == ProtoType.ApplicationData)
                        m_QHandler.EnqueueInUserQueue(message.GetBytes());
                    else
                    {
                        List<Record> records = m_MessageAdapter.ToRecords(message);
                        foreach (Record outputRecord in records)
                            m_QHandler.EnqueueInSendQueue(m_RecordAdapter.ToBytes(outputRecord));
                    }
                }
            }
            return;
        }

        internal List<Record> HandleDataToBeSent(byte[] data, int offset, int length)
        {
            byte[] payload = new byte[length];
            System.Buffer.BlockCopy(data, offset, payload, 0, length);
            IProtocolMessage message = new ApplicationProtocolMessage(payload);
            return m_MessageAdapter.ToRecords(message);
        }

        internal List<Record> CreateAlert(AlertLevel level, AlertDescription desc)
        {
            IProtocolMessage message = m_ProtocolLayer.CreateAlertMessage(level, desc);
            return m_MessageAdapter.ToRecords(message);
        }

        internal byte[] Buffer
        {
            get { return m_Buffer; }
        }

        internal ByteQueue GetSendQueue()
        {
            return m_QHandler.SendQueue;
        }

        internal ByteQueue GetUserQueue()
        {
            return m_QHandler.UserQueue;
        }
    }
}
