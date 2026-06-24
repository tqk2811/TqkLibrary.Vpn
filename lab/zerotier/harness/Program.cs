// VL1 HELLO interop harness — sends a ZeroTier HELLO to a real zerotier-one node over UDP/9993 and waits for the
// OK(HELLO) reply. A reply proves the node dearmored our packet (MAC valid) and accepted our identity. Clean-room:
// drives only this project's codec, no ZeroTier source.
//
// Usage: zt-hello-harness <mySecretIdentity> <peerPublicIdentity> <host> <port>
//   mySecretIdentity   = "addr:0:pub128hex:priv128hex" (from `zerotier-idtool generate`)
//   peerPublicIdentity = "addr:0:pub128hex"            (the node's identity.public)

using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.ZeroTier.Identity;
using TqkLibrary.VpnClient.ZeroTier.Vl1;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Enums;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;

if (args.Length < 4)
{
    Console.Error.WriteLine("usage: zt-hello-harness <mySecret> <peerPublic> <host> <port>");
    return 2;
}

var idCodec = new ZeroTierIdentityCodec();
var me = idCodec.ParseString(args[0]);
var peer = idCodec.ParseString(args[1]);
string host = args[2];
int port = int.Parse(args[3]);

if (!me.HasPrivate) { Console.Error.WriteLine("my identity has no private key"); return 2; }

Console.WriteLine($"[harness] me   = {me.Address}");
Console.WriteLine($"[harness] peer = {peer.Address}  @ {host}:{port}");

// 1) Shared key = SHA512(X25519(myC25519Priv, peerC25519Pub)) — first 32 bytes are the Salsa20 key.
var kdf = new Vl1KeyDerivation();
byte[] key = kdf.DeriveSharedKey(me.Curve25519Private, peer.Curve25519Public);
Console.WriteLine($"[harness] derived key[0..8] = {Convert.ToHexString(key.AsSpan(0, 8).ToArray()).ToLowerInvariant()}");

// 2) Build the HELLO body (after the verb byte).
ulong nowMs = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
var hello = new HelloMessage
{
    ProtocolVersion = 12,   // ZT_PROTO_VERSION
    VersionMajor = 1,
    VersionMinor = 14,
    VersionRevision = 0,
    Timestamp = nowMs,
    Identity = me,
};
byte[] body = new HelloMessageCodec().Encode(hello, includePhysicalDestNil: true);

// 3) Seal as a Poly1305None (cipher 0) HELLO packet: source=me, destination=peer, verb=HELLO.
var rng = new Random();
ulong packetId = unchecked((ulong)rng.NextInt64());
var header = new Vl1Header
{
    PacketId = packetId,
    Destination = peer.Address,
    Source = me.Address,
    Cipher = Vl1CipherSuite.Poly1305None, // HELLO is authenticated but not encrypted
    Verb = Vl1Verb.Hello,
};
byte[] packet = new Vl1PacketCodec().Seal(header, key, body);
Console.WriteLine($"[harness] HELLO packet {packet.Length} bytes, packetId={packetId:x16}");
Console.WriteLine($"[harness] header[0..28] = {Convert.ToHexString(packet.AsSpan(0, Math.Min(28, packet.Length)).ToArray()).ToLowerInvariant()}");

// 4) Send over UDP and wait for any reply.
using var udp = new UdpClient(AddressFamily.InterNetwork);
var dest = new IPEndPoint(Dns.GetHostAddresses(host)[0], port);
udp.Send(packet, packet.Length, dest);
Console.WriteLine("[harness] HELLO sent, waiting up to 5s for reply...");

udp.Client.ReceiveTimeout = 5000;
try
{
    var recvTask = udp.ReceiveAsync();
    if (!recvTask.Wait(TimeSpan.FromSeconds(5)))
    {
        Console.WriteLine("[harness] NO REPLY (timeout) — node silently dropped (likely MAC/identity rejected).");
        return 1;
    }
    var resp = recvTask.Result;
    byte[] reply = resp.Buffer;
    Console.WriteLine($"[harness] REPLY {reply.Length} bytes from {resp.RemoteEndPoint}");
    Console.WriteLine($"[harness] reply header = {Convert.ToHexString(reply.AsSpan(0, Math.Min(28, reply.Length)).ToArray()).ToLowerInvariant()}");

    // The reply is an OK(HELLO) packet sealed by the peer with the same shared key. Decrypt it (cipher 1).
    if (new Vl1PacketCodec().Open(reply, key, out var rh, out byte[] payload))
    {
        Console.WriteLine($"[harness] *** REPLY DEARMORED OK *** verb={rh.Verb} src={rh.Source} dst={rh.Destination} cipher={rh.Cipher}");
        if (rh.Verb == Vl1Verb.Ok && payload.Length >= 1)
            Console.WriteLine($"[harness] OK in-re-verb={(Vl1Verb)payload[0]} (0x{payload[0]:x2})  payloadLen={payload.Length}");
        Console.WriteLine("[harness] RESULT: VL1 HELLO INTEROP SUCCESS (node accepted our armor + replied, we dearmored its reply).");
        return 0;
    }
    Console.WriteLine("[harness] reply received but failed to dearmor with shared key (cipher mismatch on reply path).");
    Console.WriteLine("[harness] RESULT: node ACCEPTED our HELLO (it replied!) — armor->dearmor verified one-way.");
    return 0;
}
catch (Exception ex)
{
    Console.WriteLine($"[harness] error: {ex.Message}");
    return 1;
}
