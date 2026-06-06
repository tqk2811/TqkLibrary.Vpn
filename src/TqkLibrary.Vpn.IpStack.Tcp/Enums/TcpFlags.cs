namespace TqkLibrary.Vpn.IpStack.Tcp.Enums
{
    /// <summary>TCP control flags.</summary>
    [Flags]
    public enum TcpFlags : byte
    {
        None = 0,
        Fin = 1 << 0,
        Syn = 1 << 1,
        Rst = 1 << 2,
        Psh = 1 << 3,
        Ack = 1 << 4,
    }
}
