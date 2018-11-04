using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;

using SslSharp;
using SslSharp.Shared;
using SslSharp.Collections;
using SslSharp.Exceptions;
using SslSharp.ProtocolLayer;
using SslSharp.RecordLayer;
using System.Diagnostics;

namespace SslSharp.Net.Sockets
{
    public partial class SecureSocketEventArgs : EventArgs, IDisposable
    {
        public event EventHandler<SecureSocketEventArgs> Completed;

        private void OperationCallback(object sender, SocketAsyncEventArgs e)
        {
            m_InternalEventArgs = e;
            if (e.SocketError != SocketError.Success)
            {
                Console.WriteLine("Socket Error was not Success");
                Console.WriteLine(e.LastOperation);
                OnCompleted(this);
                return;
            }

            switch (e.LastOperation)
            {
                case SocketAsyncOperation.Connect:
                    if (m_SecureSocket.ConnectType == 1)
                    {
                        m_SecureSocketOperation = SecureSocketOperation.Connect;
                        SecureSocketError = SocketError.Success;
                        OnCompleted(this);
                    }
                    else if (m_SecureSocket.ConnectType == 2)
                    {
                        List<Record> records = m_SecureSocket.GetBus().StartHandshake();
                        byte[] data = Records.Merge(records);
                        Send(m_SecureSocket.InternalSocket, data);
                    }
                    break;
                case SocketAsyncOperation.Send:
                    m_BytesTransferred = Count;
                    if (m_SecureSocket.ConnectType == 1)
                    {
                        m_SecureSocketOperation = SecureSocketOperation.Send;
                        OnCompleted(this);
                    }
                    else if (m_SecureSocket.ConnectType == 2)
                    {
                        if (e.Buffer[e.Offset] == (byte)ProtoType.ApplicationData)
                        {
                            m_SecureSocketOperation = SecureSocketOperation.Send;
                            OnCompleted(this);
                        }
                        else
                            Receive(m_SecureSocket.InternalSocket);
                    }
                    break;
                #region receive
                case SocketAsyncOperation.Receive:
                    m_SecureSocketOperation = SecureSocketOperation.Receive;
                    if (e.BytesTransferred == 0)
                    {
                        Console.WriteLine("Connection Closed By Server");

                        if (m_SecureSocket == null)
                            return;
                        int received = CheckQueues(m_SecureSocket.GetBus());
                        m_SecureSocket.Close();
                        if (received != 0)
                        {
                            m_SecureSocketOperation = SecureSocketOperation.Receive;
                            m_BytesTransferred = received;
                            OnCompleted(this);
                        }

                        return;
                    }

                    if (m_SecureSocket.ConnectType == 1)
                    {
                        m_SecureSocketOperation = SecureSocketOperation.Receive;
                        m_BytesTransferred = e.BytesTransferred;
                        OnCompleted(this);
                    }
                    else if (m_SecureSocket.ConnectType == 2)
                    {
                        try
                        {
                            m_SecureSocket.GetBus().HandleReceivedData(e.Buffer, e.Offset, e.BytesTransferred);

                            int received = CheckQueues(m_SecureSocket.GetBus());
                            if (received != 0)
                            {
                                m_SecureSocketOperation = SecureSocketOperation.Receive;
                                m_BytesTransferred = received;
                                OnCompleted(this);
                            }
                        }

                        catch (SslInsufficientReceiveException)
                        {
                            int received = CheckQueues(m_SecureSocket.GetBus());
                            if (received != 0)
                            {
                                m_SecureSocketOperation = SecureSocketOperation.Receive;
                                m_BytesTransferred = received;
                                OnCompleted(this);
                            }
                            else
                                Receive(m_SecureSocket.InternalSocket);
                            return;
                        }

                        catch (SslHandshakeCompleteException)
                        {
                            m_SecureSocket.IsSecureConnected = true;
                            m_SecureSocketOperation = SecureSocketOperation.SecureConnect;
                            SecureSocketError = SocketError.Success;
                            OnCompleted(this);
                            return;
                        }

                        catch (SslAlertException exp)
                        {
                            List<Record> listofRecords = m_SecureSocket.GetBus().CreateAlert(exp.AlertLevel, exp.AlertDescription);
                            byte[] data = Records.Merge(listofRecords);
                            Send(m_SecureSocket.InternalSocket, data);
                            /* Perform all cleanup here */
                            //close socket
                            m_SecureSocket.Close();
                        }
                    }
                    break;
                #endregion
            }
        }

        internal int CheckQueues(Bus bus)
        {
            ByteQueue sendQueue = bus.GetSendQueue();

            if (sendQueue.Length > 0)
            {
                byte[] dataToSend = sendQueue.Dequeue(sendQueue.Length);
                Send(m_SecureSocket.InternalSocket, dataToSend);
            }
            ByteQueue userQueue = bus.GetUserQueue();
            if (userQueue.Length > 0)
            {
                int length = Math.Min(m_Count, userQueue.Length);
                byte[] data = userQueue.Dequeue(length);
                System.Buffer.BlockCopy(data, 0, m_Buffer, m_Offset, length);
                return length;
            }
            return 0;
        }

        private void Send(Socket socket, byte[] data)
        {
            SocketAsyncEventArgs sargs = new SocketAsyncEventArgs();
            sargs.RemoteEndPoint = m_SecureSocket.RemoteEndPoint;
            sargs.Completed += new EventHandler<SocketAsyncEventArgs>(OperationCallback);
            sargs.SetBuffer(data, 0, data.Length);
            m_SecureSocket.InternalSocket.SendAsync(sargs);
        }

        private void Receive(Socket socket)
        {
            SocketAsyncEventArgs e = new SocketAsyncEventArgs();
            e.RemoteEndPoint = socket.RemoteEndPoint;
            byte[] buffer = m_SecureSocket.GetBus().Buffer;
            e.SetBuffer(buffer, 0, buffer.Length);
            e.Completed += new EventHandler<SocketAsyncEventArgs>(OperationCallback);
            socket.ReceiveAsync(e);
        }

        protected virtual void OnCompleted(SecureSocketEventArgs e)
        {
            if (e == null)
                return;
            if (Completed != null)
                Completed(m_SecureSocket, e);
        }

        internal void RaiseCompletedForReceive(int available)
        {
            m_SecureSocketOperation = SecureSocketOperation.Receive;
            m_BytesTransferred = available;
            OnCompleted(this);
        }
    }
}
