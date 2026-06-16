namespace TqkLibrary.VpnClient.OpenVpn.Enums
{
    /// <summary>
    /// OpenVPN packet opcodes (the high 5 bits of the first byte; the low 3 bits are the key-id). See the OpenVPN
    /// wire protocol — control packets ride the reliability layer (session-id + packet-id + ACK), data packets are
    /// best-effort.
    /// </summary>
    public enum OpenVpnOpcode : byte
    {
        /// <summary>Not a valid opcode (0 is unused on the wire).</summary>
        None = 0,

        /// <summary>P_CONTROL_HARD_RESET_CLIENT_V1 — legacy client session start.</summary>
        ControlHardResetClientV1 = 1,

        /// <summary>P_CONTROL_HARD_RESET_SERVER_V1 — legacy server session start.</summary>
        ControlHardResetServerV1 = 2,

        /// <summary>P_CONTROL_SOFT_RESET_V1 — new key for an existing session (TLS renegotiation / rekey).</summary>
        ControlSoftResetV1 = 3,

        /// <summary>P_CONTROL_V1 — a reliable control-channel packet carrying TLS data.</summary>
        ControlV1 = 4,

        /// <summary>P_ACK_V1 — acknowledges received control packet-ids (no own packet-id, no payload).</summary>
        AckV1 = 5,

        /// <summary>P_DATA_V1 — best-effort data-channel packet (no peer-id).</summary>
        DataV1 = 6,

        /// <summary>P_CONTROL_HARD_RESET_CLIENT_V2 — client session start (the modern default).</summary>
        ControlHardResetClientV2 = 7,

        /// <summary>P_CONTROL_HARD_RESET_SERVER_V2 — server session start (the modern default).</summary>
        ControlHardResetServerV2 = 8,

        /// <summary>P_DATA_V2 — best-effort data-channel packet with a 3-byte peer-id.</summary>
        DataV2 = 9,

        /// <summary>P_CONTROL_HARD_RESET_CLIENT_V3 — client session start carrying a wrapped client key (tls-crypt-v2).</summary>
        ControlHardResetClientV3 = 10,

        /// <summary>P_CONTROL_WKC_V1 — control packet carrying the wrapped client key (tls-crypt-v2).</summary>
        ControlWkcV1 = 11,
    }
}
