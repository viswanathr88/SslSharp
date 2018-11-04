using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SslSharp.Exceptions
{
    class SslHandshakeCompleteException : Exception
    {
        public SslHandshakeCompleteException() :
            base("Ssl Handshake Complete")
        {
        }

    }
}
