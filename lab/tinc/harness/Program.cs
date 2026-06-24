using System.Net.Sockets;
using System.Text;
using TqkLibrary.VpnClient.Tinc.Hosts;
using TqkLibrary.VpnClient.Tinc.Meta;
using TqkLibrary.VpnClient.Tinc.Sptps;
using TqkLibrary.VpnClient.Tinc.Sptps.Enums;

// args: <hostsDir> <myName> <peerName> <serverIp:port>
// hostsDir must contain: <myName> private key file (ed25519_key.priv as base64), and hosts/<peerName> host config
// We pass: myPrivKeyFile, myName, peerHostFile, endpoint.
if (args.Length < 4)
{
    Console.WriteLine("usage: harness <myEd25519PrivBase64File> <myName> <peerHostFile> <ip:port> [peerName]");
    return 1;
}

string myPrivFile = args[0];
string myName = args[1];
string peerHostFile = args[2];
string[] hp = args[3].Split(':');
string host = hp[0];
int port = hp.Length > 1 ? int.Parse(hp[1]) : 655;

// my Ed25519 private key: tinc ed25519_key.priv is base64. May be 64 bytes (seed||pub) or 96. Take first 32 (seed).
string privText = File.ReadAllText(myPrivFile).Trim();
// strip any header lines like "-----BEGIN ED25519 PRIVATE KEY-----"
var b64Lines = new List<string>();
foreach (var l in privText.Split('\n'))
{
    string t = l.Trim();
    if (t.Length == 0 || t.StartsWith("-----")) continue;
    b64Lines.Add(t);
}
byte[] privFull = TincHostConfig.DecodeBase64Key(string.Join("", b64Lines));
byte[] myPriv = privFull.Length >= 32 ? privFull[..32] : privFull;
Console.WriteLine($"[*] my Ed25519 priv: {privFull.Length} bytes decoded, using first 32 as seed");

// peer host config → Ed25519 public key + name
var peerCfg = TincHostConfig.Parse(File.ReadAllText(peerHostFile), Path.GetFileName(peerHostFile));
string peerName = args.Length > 4 ? args[4] : (peerCfg.Name ?? Path.GetFileName(peerHostFile));
byte[] peerPub = peerCfg.Ed25519PublicKey ?? throw new Exception("peer host file missing Ed25519PublicKey");
Console.WriteLine($"[*] peer={peerName} Ed25519 pub {peerPub.Length}B");

using var tcp = new TcpClient();
tcp.Connect(host, port);
var stream = tcp.GetStream();
Console.WriteLine($"[*] TCP connected to {host}:{port}");

// 1) send ID cleartext (we are outgoing → initiator)
var id = TincMetaRequest.Id(myName, 17, 7);
byte[] idBytes = id.ToBytes();
stream.Write(idBytes, 0, idBytes.Length);
Console.WriteLine($"[>] ID sent: {Encoding.ASCII.GetString(idBytes).TrimEnd()}");

// 2) read peer ID line (cleartext, until '\n')
string peerIdLine = ReadLine(stream);
Console.WriteLine($"[<] peer ID: {peerIdLine}");
var peerId = TincMetaRequest.Parse(peerIdLine);
string serverName = peerId.Arguments.Count > 0 ? peerId.Arguments[0] : peerName;

// 3) SPTPS handshake. label = "tinc TCP key expansion <initiator=me> <responder=server>" + NUL
byte[] label = SptpsHandshake.BuildMetaLabel(myName, serverName);
Console.WriteLine($"[*] label='{Encoding.ASCII.GetString(label).TrimEnd('\0')}' (len {label.Length})");

var hs = new SptpsHandshake(initiator: true, myPriv, peerPub, label);
var rec = new SptpsRecordLayer();

// initiator sends KEX immediately
byte[] myKex = hs.CreateKex();
byte[] kexFrame = rec.EncodeHandshake(myKex);
stream.Write(kexFrame, 0, kexFrame.Length);
Console.WriteLine($"[>] KEX sent ({myKex.Length}B handshake record, frame {kexFrame.Length}B)");

// read server KEX (handshake record, plaintext)
var buf = new List<byte>();
byte[] serverKex = ReadOneRecord(stream, rec, buf, out byte t1);
Console.WriteLine($"[<] server record type={t1} len={serverKex.Length}");
if (t1 != (byte)SptpsRecordType.Handshake) { Console.WriteLine("[!] expected handshake KEX"); }
hs.ConsumeKex(serverKex);
Console.WriteLine("[*] consumed server KEX, derived key material");

// send our SIG
byte[] mySig = hs.CreateSig();
byte[] sigFrame = rec.EncodeHandshake(mySig);
stream.Write(sigFrame, 0, sigFrame.Length);
Console.WriteLine($"[>] SIG sent ({mySig.Length}B)");

// read server SIG
byte[] serverSig = ReadOneRecord(stream, rec, buf, out byte t2);
Console.WriteLine($"[<] server record type={t2} len={serverSig.Length}");
bool sigOk = hs.ConsumeSig(serverSig);
Console.WriteLine(sigOk ? "[✓] server SIG VERIFIED — SPTPS authentication OK" : "[✗] server SIG verification FAILED");
if (!sigOk) return 2;

// enable encryption with derived directional keys
rec.EnableEncryption(hs.OutCipherKey, hs.InCipherKey);
Console.WriteLine("[*] encryption enabled. Reading first encrypted application record...");

// read one encrypted app record — if it decrypts, our derived keys match tinc's → full interop
try
{
    byte[] app = ReadOneRecord(stream, rec, buf, out byte t3);
    string text = Encoding.ASCII.GetString(app).TrimEnd('\n');
    Console.WriteLine($"[✓] DECRYPTED app record type={t3}: '{text}'");
    Console.WriteLine("[✓✓] SPTPS HANDSHAKE + RECORD LAYER INTEROP OK with real tincd");
}
catch (Exception ex)
{
    Console.WriteLine($"[~] no app record decrypted ({ex.Message}); but SIG verified = handshake auth OK");
}

return 0;

// ---- helpers ----
static string ReadLine(NetworkStream s)
{
    var sb = new StringBuilder();
    int b;
    while ((b = s.ReadByte()) != -1)
    {
        if (b == '\n') break;
        if (b != '\r') sb.Append((char)b);
    }
    return sb.ToString();
}

static byte[] ReadOneRecord(NetworkStream s, SptpsRecordLayer rec, List<byte> buf, out byte type)
{
    byte[] tmp = new byte[4096];
    while (true)
    {
        var result = rec.TryDecodeRecord(buf.ToArray(), out type, out byte[] data, out int consumed);
        if (result == SptpsDecodeResult.Ok)
        {
            buf.RemoveRange(0, consumed);
            return data;
        }
        if (result == SptpsDecodeResult.AuthFailed)
            throw new Exception("record auth failed (decrypt mismatch)");
        // NeedMore → read
        int n = s.Read(tmp, 0, tmp.Length);
        if (n <= 0) throw new Exception("connection closed by peer");
        for (int i = 0; i < n; i++) buf.Add(tmp[i]);
    }
}
