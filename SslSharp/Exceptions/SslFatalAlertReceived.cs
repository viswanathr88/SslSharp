using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SslSharp.Exceptions
{
    internal class SslFatalAlertReceived : Exception
    {
        public SslFatalAlertReceived() : base("TLS Error: A Fatal Alert was Received") { }
    }
}
