using System;
using System.Collections.Generic;
using System.Linq;

namespace SslSharp.Collections
{
    class ByteQueue
    {
        private LinkedList<byte[]> m_Queue = null;
        private int m_AvailableInQueue = 0;

        public ByteQueue()
        {
            m_Queue = new LinkedList<byte[]>();
        }

        public void Enqueue(byte[] data) 
        {
            m_Queue.AddLast(data);
            m_AvailableInQueue += data.Length;
        }
        public void EnqueueFirst(byte[] data)
        {
            m_Queue.AddFirst(data);
            m_AvailableInQueue += data.Length;
        }

        public byte[] Peek(int numberOfBytes)
        {
            if (m_AvailableInQueue < numberOfBytes)
                throw new ArgumentOutOfRangeException();

            byte[] result = new byte[numberOfBytes];
            int obtainedSoFar = 0;

            for (int i = 0; i < m_Queue.Count; i++)
            {
                byte[] chunk = m_Queue.ElementAt(i);
                if (chunk.Length < (numberOfBytes - obtainedSoFar))
                {
                    System.Buffer.BlockCopy(chunk, 0, result, obtainedSoFar, chunk.Length);
                    obtainedSoFar += chunk.Length;
                }
                else
                {
                    System.Buffer.BlockCopy(chunk, 0, result, obtainedSoFar, (numberOfBytes - obtainedSoFar));
                    break;
                }
            }
            return result;   
        }
        public byte[] Dequeue(int numberOfBytes)
        {
            if (m_AvailableInQueue < numberOfBytes)
                throw new ArgumentOutOfRangeException();

            int obtainedsoFar = 0;
            byte[] result = null;

            while (obtainedsoFar < numberOfBytes)
            {
                byte[] data = m_Queue.First();
                int newLength = (numberOfBytes - obtainedsoFar);
                if (data.Length >= (newLength))
                {
                    byte[] newResult = new byte[newLength];
                    System.Buffer.BlockCopy(data, 0, newResult, 0, newLength);
                    obtainedsoFar += newLength;
                    result = ByteArray.Concat(result, newResult);
                    if (data.Length != newLength)
                    {
                        byte[] newArray = new byte[data.Length - newLength];
                        System.Buffer.BlockCopy(data, newLength, newArray, 0, newArray.Length);
                        m_AvailableInQueue -= data.Length;
                        m_Queue.RemoveFirst();
                        m_Queue.AddFirst(newArray);
                        m_AvailableInQueue += newArray.Length;
                    }
                    else
                    {
                        m_AvailableInQueue -= data.Length;
                        m_Queue.RemoveFirst();
                    }

                }
                else
                {
                    result = ByteArray.Concat(result, data);
                    obtainedsoFar += data.Length;
                    m_AvailableInQueue -= data.Length;
                    m_Queue.RemoveFirst();
                }

            }
            return result;
        }

        public int Length
        {
            get { return m_AvailableInQueue; }
        }
    }
}
