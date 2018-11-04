using System;
using System.Net;
using System.Collections;
using System.Net.Sockets;
using SslSharp;
using SslSharp.Collections;
using SslSharp.RecordLayer;
using System.Collections.Generic;

namespace SslSharp.Net.Sockets
{
    /// <summary>
    /// Creates a TCP socket which supports SSL/TLS
    /// </summary>
    public sealed class SecureSocket : IDisposable
    {
        private Socket m_InternalSocket;
        private Bus m_Bus;
        private bool m_IsSecureConnected;
        private int m_ConnectType = 0; //2 = SecureConnect. 1 = Connect
        private bool m_Disposed = false;

        /// <summary>
        /// Creates a secure socket over a TCP connection
        /// </summary>
        public SecureSocket()
        {
            this.m_InternalSocket = new Socket(AddressFamily.InterNetwork, 
                SocketType.Stream, ProtocolType.Tcp);
            //this.m_Bus = new Bus();
            m_IsSecureConnected = false;
            m_Disposed = false;
        }

        /// <summary>
        /// Gets or sets the internal tcp socket
        /// </summary>
        internal Socket InternalSocket
        {
            get { return m_InternalSocket; }
        }
        /// <summary>
        /// Gets the address family of the secure socket
        /// </summary>
        public AddressFamily AddressFamily
        {
            get { return m_InternalSocket.AddressFamily; }
        }
        /// <summary>
        /// Gets a value indicating whether the socket is connected to a remote host
        /// </summary>
        public bool Connected
        {
            get { return m_InternalSocket.Connected; }
        }
        /// <summary>
        /// Gets the protocol type of the secure socket
        /// </summary>
        public ProtocolType ProtocolType 
        {
            get { return m_InternalSocket.ProtocolType; }
        }
        /// <summary>
        /// Gets the remote endpoint
        /// </summary>
        public EndPoint RemoteEndPoint
        {
            get 
            {
                if (m_Disposed == true)
                    throw new ObjectDisposedException("m_SecureSocket");
                return m_InternalSocket.RemoteEndPoint; 
            }
        }
        /// <summary>
        /// Connects asynchronously to a remote host
        /// </summary>
        /// <param name="e">The SecureSocketEventArgs object to use for this asynchronous socket operation</param>
        /// <returns>Type: System.Boolean
        /// Returns true if the I/O is pending, false if the operation completed synchronously</returns>
        public bool ConnectAsync(SecureSocketEventArgs e)
        {
            if (m_Disposed == true)
                throw new ObjectDisposedException("m_SecureSocket");

            if (m_InternalSocket.Connected)
                return true;
            m_ConnectType = 1;    
            e.SetSecureSocket(this);
            bool result = m_InternalSocket.ConnectAsync(e.InternalEventArgs);
            return result;
        }
        /// <summary>
        /// Initiates a handshake with a remote host
        /// </summary>
        /// <param name="e">The SslSocketArgs object to use for this asynchronous socket operation</param>
        public bool SecureConnectAsync(SecureSocketEventArgs e)
        {
            if (m_Disposed == true)
                throw new ObjectDisposedException("m_SecureSocket");

            bool result;
            m_ConnectType = 2;
            if (!m_InternalSocket.Connected)
                m_IsSecureConnected = false;

            if (m_IsSecureConnected)
                return true;

            if (m_InternalSocket.Connected)
            {
                e.SetSecureSocket(this);
                m_Bus = new Bus();
                List<Record> listOfRecords = m_Bus.StartHandshake();
                byte[] data = Records.Merge(listOfRecords);
                Console.WriteLine("Internal Socket is connected. " + BitConverter.ToString(data));
                e.SetBufferInternal(data, 0, data.Length);
                result = m_InternalSocket.SendAsync(e.InternalEventArgs);
            }
            else
            {
                e.SetSecureSocket(this);
                m_Bus = new Bus();
                result = m_InternalSocket.ConnectAsync(e.InternalEventArgs);
            }
            return result;
        }
        /// <summary>
        /// Sends data asynchronously to a remote host
        /// </summary>
        /// <param name="e">The SecureSocketEventArgs object to use for this asynchronous socket operation</param>
        /// <returns></returns>
        public bool SendAsync(SecureSocketEventArgs e)
        {
            if (m_Disposed == true)
                throw new ObjectDisposedException("m_SecureSocket");

            e.SetSecureSocket(this);
            List<Record> listOfRecords = m_Bus.HandleDataToBeSent(e.Buffer, e.Offset, e.Count);
            byte[] data = Records.Merge(listOfRecords);
            e.SetBufferInternal(data, 0, data.Length);
            bool result = m_InternalSocket.SendAsync(e.InternalEventArgs);
            return result;
        }
        /// <summary>
        /// Receive data asynchronously from a remote host
        /// </summary>
        /// <param name="e">The SslSocketArgs object to use for this asynchronous socket operation</param>
        /// <returns>Type: System.Boolean
        /// Returns true if the I/O is pending, false if the operation completed synchronously</returns>
        public bool ReceiveAsync(SecureSocketEventArgs e)
        {
            if (m_Disposed)
                throw new ObjectDisposedException("m_SecureSocket");

            int available = e.CheckQueues(m_Bus);
            if (available != 0)
            {
                e.RaiseCompletedForReceive(available);
                return true;
            }
            else
            {
                e.SetSecureSocket(this);
                e.SetBufferForReceive();
                bool result = m_InternalSocket.ReceiveAsync(e.InternalEventArgs);
                return result;
            }
        }

        public void Close()
        {
            if (m_InternalSocket != null)
                m_InternalSocket.Close();
            Dispose();
        }

        /* internal methods */
        internal Bus GetBus()
        {
            return m_Bus;
        }

        internal int ConnectType
        {
            get { return this.m_ConnectType; }
        }

        internal bool IsSecureConnected
        {
            get { return this.m_IsSecureConnected; }
            set { this.m_IsSecureConnected = value; }
        }

        public void Dispose()
        {
            if (m_Disposed == false)
            {
                m_IsSecureConnected = false;
                m_ConnectType = 0;
                m_Bus = null;
                m_Disposed = true;
            }
        }
    }
}
