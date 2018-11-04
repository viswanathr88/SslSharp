using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.ProtocolLayer;

namespace SslSharp.Exceptions
{
    class SslAlertException : Exception
    {
        AlertLevel l;
        AlertDescription e;

        public SslAlertException(AlertLevel al, AlertDescription desc)
        {
            l = al;
            e = desc;
        }

        public AlertLevel AlertLevel
        {
            get { return l; }
        }

        public AlertDescription AlertDescription
        {
            get { return e; }
        }
    }
}
