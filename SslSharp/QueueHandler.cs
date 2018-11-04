using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.Collections;
using SslSharp.Exceptions;

namespace SslSharp
{
    class QueueHandler
    {
        ByteQueue userDataQueue;
        ByteQueue sendQueue;

        public QueueHandler()
        {
            userDataQueue = new ByteQueue();
            sendQueue = new ByteQueue();
        }

        internal void EnqueueInUserQueue(byte[] data)
        {
            userDataQueue.Enqueue(data);
        }

        internal void EnqueueInSendQueue(byte[] data)
        {
            sendQueue.Enqueue(data);
        }

        internal ByteQueue SendQueue
        {
            get { return sendQueue; }
        }

        internal ByteQueue UserQueue
        {
            get { return userDataQueue; }
        }
    }
}
