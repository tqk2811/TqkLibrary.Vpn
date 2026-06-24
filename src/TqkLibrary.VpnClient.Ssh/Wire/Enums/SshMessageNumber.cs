namespace TqkLibrary.VpnClient.Ssh.Wire.Enums
{
    /// <summary>
    /// SSH message numbers (the first payload byte of a binary packet) from RFC 4253 (transport), RFC 4252 (userauth) and
    /// RFC 4254 (connection), plus the ECDH key-exchange messages (RFC 5656 / RFC 8731). Only the numbers this minimal
    /// client uses are named.
    /// </summary>
    public enum SshMessageNumber : byte
    {
        /// <summary>SSH_MSG_DISCONNECT (RFC 4253 §11.1).</summary>
        Disconnect = 1,

        /// <summary>SSH_MSG_IGNORE (RFC 4253 §11.2).</summary>
        Ignore = 2,

        /// <summary>SSH_MSG_UNIMPLEMENTED (RFC 4253 §11.4).</summary>
        Unimplemented = 3,

        /// <summary>SSH_MSG_DEBUG (RFC 4253 §11.3).</summary>
        Debug = 4,

        /// <summary>SSH_MSG_SERVICE_REQUEST (RFC 4253 §10).</summary>
        ServiceRequest = 5,

        /// <summary>SSH_MSG_SERVICE_ACCEPT (RFC 4253 §10).</summary>
        ServiceAccept = 6,

        /// <summary>SSH_MSG_KEXINIT (RFC 4253 §7.1).</summary>
        KexInit = 20,

        /// <summary>SSH_MSG_NEWKEYS (RFC 4253 §7.3).</summary>
        NewKeys = 21,

        /// <summary>SSH_MSG_KEX_ECDH_INIT (RFC 5656 §4) — also used by curve25519-sha256 (RFC 8731).</summary>
        KexEcdhInit = 30,

        /// <summary>SSH_MSG_KEX_ECDH_REPLY (RFC 5656 §4).</summary>
        KexEcdhReply = 31,

        /// <summary>SSH_MSG_USERAUTH_REQUEST (RFC 4252 §5).</summary>
        UserAuthRequest = 50,

        /// <summary>SSH_MSG_USERAUTH_FAILURE (RFC 4252 §5.1).</summary>
        UserAuthFailure = 51,

        /// <summary>SSH_MSG_USERAUTH_SUCCESS (RFC 4252 §5.1).</summary>
        UserAuthSuccess = 52,

        /// <summary>SSH_MSG_USERAUTH_BANNER (RFC 4252 §5.4).</summary>
        UserAuthBanner = 53,

        /// <summary>SSH_MSG_USERAUTH_PK_OK (RFC 4252 §7) — shares number 60 with other auth-specific replies.</summary>
        UserAuthPkOk = 60,

        /// <summary>SSH_MSG_GLOBAL_REQUEST (RFC 4254 §4).</summary>
        GlobalRequest = 80,

        /// <summary>SSH_MSG_REQUEST_SUCCESS (RFC 4254 §4).</summary>
        RequestSuccess = 81,

        /// <summary>SSH_MSG_REQUEST_FAILURE (RFC 4254 §4).</summary>
        RequestFailure = 82,

        /// <summary>SSH_MSG_CHANNEL_OPEN (RFC 4254 §5.1).</summary>
        ChannelOpen = 90,

        /// <summary>SSH_MSG_CHANNEL_OPEN_CONFIRMATION (RFC 4254 §5.1).</summary>
        ChannelOpenConfirmation = 91,

        /// <summary>SSH_MSG_CHANNEL_OPEN_FAILURE (RFC 4254 §5.1).</summary>
        ChannelOpenFailure = 92,

        /// <summary>SSH_MSG_CHANNEL_WINDOW_ADJUST (RFC 4254 §5.2).</summary>
        ChannelWindowAdjust = 93,

        /// <summary>SSH_MSG_CHANNEL_DATA (RFC 4254 §5.2).</summary>
        ChannelData = 94,

        /// <summary>SSH_MSG_CHANNEL_EXTENDED_DATA (RFC 4254 §5.2).</summary>
        ChannelExtendedData = 95,

        /// <summary>SSH_MSG_CHANNEL_EOF (RFC 4254 §5.3).</summary>
        ChannelEof = 96,

        /// <summary>SSH_MSG_CHANNEL_CLOSE (RFC 4254 §5.3).</summary>
        ChannelClose = 97,

        /// <summary>SSH_MSG_CHANNEL_REQUEST (RFC 4254 §5.4).</summary>
        ChannelRequest = 98,

        /// <summary>SSH_MSG_CHANNEL_SUCCESS (RFC 4254 §5.4).</summary>
        ChannelSuccess = 99,

        /// <summary>SSH_MSG_CHANNEL_FAILURE (RFC 4254 §5.4).</summary>
        ChannelFailure = 100,
    }
}
