using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Net;
using System.Net.Sockets;

using SslSharp;
using SslSharp.Collections;

namespace SslSharp.Net.Sockets
{
    public enum SecureSocketOperation
    {
        // Summary:
        //     None of the socket operations.
        None = 0,
        //
        // Summary:
        //     A socket Connect operation.
        Connect = 1,
        //
        // Summary:
        //     A socket Disconnect operation.
        Disconnect = 2,
        //
        // Summary:
        //     A socket Receive operation.
        Receive = 3,
        //
        // Summary:
        //     A socket Send operation.
        Send = 4,
        //
        // Summary:
        //     A Ssl Handshake operation.
        SecureConnect = 5
    }

    public partial class SecureSocketEventArgs : EventArgs, IDisposable
    {
        private SecureSocket m_SecureSocket;
        private SocketAsyncEventArgs m_InternalEventArgs;
        private int m_BytesTransferred = 0;
        private SecureSocketOperation m_SecureSocketOperation;

        private Byte[] m_Buffer;
        private int m_Count;
        private int m_Offset;

        /// <summary>
        /// Creates a SecureSocketEventArgs for asynchronous secure sockets
        /// </summary>
        public SecureSocketEventArgs()
        {
            m_InternalEventArgs = new SocketAsyncEventArgs();
            m_InternalEventArgs.Completed += new EventHandler<SocketAsyncEventArgs>(OperationCallback);
        }
        public void Dispose()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Returns the buffer that holds the data after the socket operation
        /// </summary>
        public Byte[] Buffer
        {
            get { return m_Buffer; }
        }
        /// <summary>
        /// Returns the length of usable area in the buffer
        /// </summary>
        public int Count
        {
            get { return this.m_Count; }
        }
        /// <summary>
        /// Returns the offset into the buffer from where to begin using the buffer
        /// </summary>
        public int Offset
        {
            get { return this.m_Offset; }
        }
        /// <summary>
        /// Gets the number of bytes transferred after the socket operation
        /// </summary>
        public int BytesTransferred
        {
            get { return m_BytesTransferred; }
        }
        /// <summary>
        /// Gets the last socket operation
        /// </summary>
        public SecureSocketOperation LastOperation
        {
            get { return m_SecureSocketOperation; }
        }
        /// <summary>
        /// Gets the remote end point
        /// </summary>
        public EndPoint RemoteEndPoint
        {
            get { return m_InternalEventArgs.RemoteEndPoint; }
            set { m_InternalEventArgs.RemoteEndPoint = value; }
        }
        /// <summary>
        /// Gets the secure socket error of the last socket operation
        /// </summary>
        public SocketError SecureSocketError
        {
            get { return m_InternalEventArgs.SocketError; }
            set { m_InternalEventArgs.SocketError = value; }
        }
        /// <summary>
        /// Sets the secure socket in the Event Args object
        /// </summary>
        /// <param name="secureSocket"></param>
        internal void SetSecureSocket(SecureSocket secureSocket)
        {
            if (secureSocket == null)
                throw new ArgumentNullException();
            else
                this.m_SecureSocket = secureSocket;
        }
        /// <summary>
        /// Get the internal socket async event args object
        /// </summary>
        internal SocketAsyncEventArgs InternalEventArgs
        {
            get { return m_InternalEventArgs; }
        }
        /// <summary>
        /// Sets the buffer to use for the socket operation
        /// </summary>
        /// <param name="buff">A Byte Buffer</param>
        /// <param name="offset">Offset into the byte buffer</param>
        /// <param name="count">Length of Byte Buffer to use in the socket operation</param>
        public void SetBuffer(byte[] buff, int offset, int count)
        {
            //Store a reference to the user buffer for future
            this.m_Buffer = buff;
            this.m_Offset = offset;
            this.m_Count = count;
        }
        /// <summary>
        /// Sets the buffer for the internal socket async event args object
        /// </summary>
        /// <param name="buff">A Byte Buffer</param>
        /// <param name="offset">Offset into the byte buffer</param>
        /// <param name="count">Length of Byte Buffer to use in the socket operation</param>
        internal void SetBufferInternal(byte[] buff, int offset, int count)
        {
            m_InternalEventArgs.SetBuffer(buff, offset, count);
        }

        internal void SetBufferForReceive()
        {
            Bus bus = m_SecureSocket.GetBus();
            m_InternalEventArgs.SetBuffer(bus.Buffer, 
                0, bus.Buffer.Length);
        }

        internal void StoreInUserBuffer(byte[] data)
        {
            System.Buffer.BlockCopy(m_Buffer, m_Offset, data, 0, data.Length);
            m_SecureSocketOperation = SecureSocketOperation.Receive;
            m_BytesTransferred = data.Length;
            OnCompleted(this);
        }
    }
}
