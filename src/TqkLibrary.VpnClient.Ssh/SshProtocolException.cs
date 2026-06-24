using System.Runtime.Serialization;

namespace TqkLibrary.VpnClient.Ssh
{
    /// <summary>Raised when an SSH protocol exchange fails (bad MAC, malformed packet, algorithm negotiation failure, a peer DISCONNECT, an auth rejection or a channel-open failure).</summary>
    [Serializable]
    public class SshProtocolException : Exception
    {
        /// <summary>Creates the exception with a message.</summary>
        public SshProtocolException(string message) : base(message) { }

        /// <summary>Creates the exception with a message and inner exception.</summary>
        public SshProtocolException(string message, Exception innerException) : base(message, innerException) { }

        /// <summary>Serialization constructor.</summary>
        protected SshProtocolException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
