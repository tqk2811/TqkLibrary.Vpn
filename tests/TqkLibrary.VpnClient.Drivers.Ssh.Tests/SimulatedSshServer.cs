using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Ssh.Channel;
using TqkLibrary.VpnClient.Ssh.Cipher;
using TqkLibrary.VpnClient.Ssh.Transport;
using TqkLibrary.VpnClient.Ssh.Wire;
using TqkLibrary.VpnClient.Ssh.Wire.Enums;

namespace TqkLibrary.VpnClient.Drivers.Ssh.Tests
{
    /// <summary>
    /// A minimal in-process SSH-2 <b>server</b> for offline driver tests. It runs the server side of the same handshake
    /// the <c>SshClient</c> drives — version exchange, KEXINIT, the server half of curve25519-sha256 (own ephemeral,
    /// shared secret, exchange hash, ed25519 host-key signature over H), NEWKEYS, accept publickey/password userauth and a
    /// <c>tun@openssh.com</c> channel — then echoes IP packets back over the tun channel (so the client's send→receive
    /// data plane round-trips). Built entirely on the SSH protocol library's public codecs (no copied OpenSSH code); it is
    /// the self-pair counterpart that exercises the client end-to-end. Supports the chacha20-poly1305@openssh.com and
    /// aes256-gcm@openssh.com ciphers (negotiated by client preference).
    /// </summary>
    public sealed class SimulatedSshServer
    {
        readonly IByteStreamTransport _stream;
        readonly byte[] _hostPrivate;      // server ed25519 seed
        readonly byte[] _hostPublic;       // server ed25519 public
        readonly byte[]? _authorizedClientPublic; // client ed25519 public for publickey auth (null → accept password "pw")
        readonly string[] _ciphers;
        SshPacketCodec? _codec;
        uint _channelRemote;
        uint _channelLocal = 17;

        public SimulatedSshServer(IByteStreamTransport stream, byte[] hostPrivateSeed, byte[]? authorizedClientPublic = null, string? onlyCipher = null)
        {
            _stream = stream;
            _hostPrivate = hostPrivateSeed;
            _hostPublic = new Ed25519Signer().DerivePublicKey(hostPrivateSeed);
            _authorizedClientPublic = authorizedClientPublic;
            _ciphers = onlyCipher is null
                ? new[] { "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com" }
                : new[] { onlyCipher };
        }

        public byte[] HostPublicKey => _hostPublic;

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            // 1) Version exchange (server side).
            var version = new SshVersionExchange(_stream);
            // Re-implement the server side: send banner, read the client's.
            byte[] banner = System.Text.Encoding.ASCII.GetBytes("SSH-2.0-SimulatedSshServer\r\n");
            await _stream.WriteAsync(banner, cancellationToken);
            (string clientId, byte[] leftover) = await ReadClientIdAsync(cancellationToken);
            const string serverId = "SSH-2.0-SimulatedSshServer";

            _codec = new SshPacketCodec(_stream);
            if (leftover.Length > 0) _codec.PushBackBytes(leftover);

            // 2) KEXINIT.
            SshKexInit serverKexInit = BuildServerKexInit();
            byte[] serverKexInitPayload = serverKexInit.Encode();
            await _codec.WritePacketAsync(serverKexInitPayload, cancellationToken);

            byte[] clientKexInitPayload = await ReadExpectingAsync(SshMessageNumber.KexInit, cancellationToken);
            SshKexInit clientKexInit = SshKexInit.Decode(clientKexInitPayload);
            string cipherCs = SshKexInit.Negotiate(clientKexInit.EncryptionAlgorithmsClientToServer, serverKexInit.EncryptionAlgorithmsClientToServer)!;
            string cipherSc = SshKexInit.Negotiate(clientKexInit.EncryptionAlgorithmsServerToClient, serverKexInit.EncryptionAlgorithmsServerToClient)!;

            // 3) curve25519 KEX (server side).
            byte[] initPayload = await ReadExpectingAsync(SshMessageNumber.KexEcdhInit, cancellationToken);
            var ir = new SshReader(initPayload);
            ir.ReadByte();
            byte[] clientPublic = ir.ReadStringBytes(); // Q_C

            var dh = new Curve25519DhGroup();
            byte[] serverEphPriv = dh.GeneratePrivateKey();
            byte[] serverEphPub = dh.DerivePublicValue(serverEphPriv); // Q_S
            byte[] shared = dh.DeriveSharedSecret(serverEphPriv, clientPublic);

            // Host-key blob K_S = string "ssh-ed25519" || string pub.
            var ksW = new SshWriter();
            ksW.WriteString("ssh-ed25519");
            ksW.WriteString(_hostPublic);
            byte[] hostKeyBlob = ksW.ToArray();

            // Exchange hash H = SHA256(V_C||V_S||I_C||I_S||K_S||Q_C||Q_S||K).
            var hw = new SshWriter();
            hw.WriteString(System.Text.Encoding.ASCII.GetBytes(clientId));
            hw.WriteString(System.Text.Encoding.ASCII.GetBytes(serverId));
            hw.WriteString(clientKexInitPayload);
            hw.WriteString(serverKexInitPayload);
            hw.WriteString(hostKeyBlob);
            hw.WriteString(clientPublic);
            hw.WriteString(serverEphPub);
            hw.WriteMpint(shared);
            byte[] exchangeHash;
            using (var sha = System.Security.Cryptography.SHA256.Create()) exchangeHash = sha.ComputeHash(hw.ToArray());

            byte[] sig = new Ed25519Signer().Sign(_hostPrivate, exchangeHash);
            var sigW = new SshWriter();
            sigW.WriteString("ssh-ed25519");
            sigW.WriteString(sig);

            var replyW = new SshWriter();
            replyW.WriteByte((byte)SshMessageNumber.KexEcdhReply);
            replyW.WriteString(hostKeyBlob);
            replyW.WriteString(serverEphPub);
            replyW.WriteString(sigW.ToArray());
            await _codec.WritePacketAsync(replyW.ToArray(), cancellationToken);

            // 4) NEWKEYS — install ciphers (server: outbound = s→c, inbound = c→s).
            await _codec.WritePacketAsync(new[] { (byte)SshMessageNumber.NewKeys }, cancellationToken);
            await ReadExpectingAsync(SshMessageNumber.NewKeys, cancellationToken);

            var kex = new ServerKex(shared, exchangeHash);
            _codec.SetOutboundCipher(BuildCipher(cipherSc, kex, exchangeHash, serverToClient: true));
            _codec.SetInboundCipher(BuildCipher(cipherCs, kex, exchangeHash, serverToClient: false));

            // 5) Userauth — accept service request, then accept the first publickey/password request.
            byte[] svc = await ReadExpectingAsync(SshMessageNumber.ServiceRequest, cancellationToken);
            var svcW = new SshWriter();
            svcW.WriteByte((byte)SshMessageNumber.ServiceAccept);
            svcW.WriteString("ssh-userauth");
            await _codec.WritePacketAsync(svcW.ToArray(), cancellationToken);

            byte[] authReq = await ReadExpectingAsync(SshMessageNumber.UserAuthRequest, cancellationToken);
            bool authOk = VerifyAuth(authReq);
            await _codec.WritePacketAsync(new[] { (byte)(authOk ? SshMessageNumber.UserAuthSuccess : SshMessageNumber.UserAuthFailure) }, cancellationToken);
            if (!authOk) return;

            // 6) Channel open tun@openssh.com.
            byte[] open = await ReadExpectingAsync(SshMessageNumber.ChannelOpen, cancellationToken);
            var or = new SshReader(open);
            or.ReadByte();
            string channelType = or.ReadStringUtf8();
            _channelRemote = or.ReadUInt32();
            or.ReadUInt32(); // window
            or.ReadUInt32(); // max packet
            // mode, unit
            var confW = new SshWriter();
            confW.WriteByte((byte)SshMessageNumber.ChannelOpenConfirmation);
            confW.WriteUInt32(_channelRemote);
            confW.WriteUInt32(_channelLocal);
            confW.WriteUInt32(2 * 1024 * 1024);
            confW.WriteUInt32(32 * 1024);
            await _codec.WritePacketAsync(confW.ToArray(), cancellationToken);

            // 7) Echo IP packets: each inbound CHANNEL_DATA → swap a marker byte → send back.
            while (!cancellationToken.IsCancellationRequested)
            {
                byte[] msg;
                try { msg = await _codec.ReadPacketAsync(cancellationToken); }
                catch { return; }
                if (msg.Length == 0) continue;
                var r = new SshReader(msg);
                var t = (SshMessageNumber)r.ReadByte();
                if (t == SshMessageNumber.ChannelData)
                {
                    r.ReadUInt32(); // recipient (ours)
                    var data = r.ReadString();
                    if (SshTunFraming.TryDecapsulate(data, out var ip, out _) && ip.Length > 0)
                    {
                        // Echo the same IP packet straight back (the test asserts the round-trip).
                        byte[] echoTun = SshTunFraming.Encapsulate(ip);
                        var dw = new SshWriter();
                        dw.WriteByte((byte)SshMessageNumber.ChannelData);
                        dw.WriteUInt32(_channelRemote);
                        dw.WriteString(echoTun);
                        await _codec.WritePacketAsync(dw.ToArray(), cancellationToken);
                    }
                }
                else if (t == SshMessageNumber.ChannelClose || t == SshMessageNumber.Disconnect)
                {
                    return;
                }
            }
        }

        bool VerifyAuth(byte[] authReq)
        {
            var r = new SshReader(authReq);
            r.ReadByte();
            r.ReadStringUtf8(); // user
            r.ReadStringUtf8(); // service
            string method = r.ReadStringUtf8();
            if (method == "publickey" && _authorizedClientPublic is not null)
            {
                r.ReadBoolean();            // has-signature
                r.ReadStringUtf8();         // alg
                byte[] keyBlob = r.ReadStringBytes();
                var kr = new SshReader(keyBlob);
                kr.ReadStringUtf8();        // "ssh-ed25519"
                byte[] clientPub = kr.ReadStringBytes();
                return clientPub.AsSpan().SequenceEqual(_authorizedClientPublic);
            }
            if (method == "password")
            {
                r.ReadBoolean();
                string pw = r.ReadStringUtf8();
                return pw == "pw";
            }
            return false;
        }

        SshKexInit BuildServerKexInit()
        {
            var k = SshKexInit.CreateClientDefault();
            // The simulated server advertises only the cipher(s) under test, so the client-preference negotiation lands
            // on the cipher the test wants to exercise.
            k.EncryptionAlgorithmsClientToServer = _ciphers;
            k.EncryptionAlgorithmsServerToClient = _ciphers;
            return k;
        }

        ISshPacketCipher BuildCipher(string name, ServerKex kex, byte[] sessionId, bool serverToClient)
        {
            char ivLetter = serverToClient ? 'B' : 'A';
            char keyLetter = serverToClient ? 'D' : 'C';
            switch (name)
            {
                case "chacha20-poly1305@openssh.com":
                    return new ChaCha20Poly1305OpenSshCipher(kex.DeriveKey(keyLetter, sessionId, ChaCha20Poly1305OpenSshCipher.KeyMaterialBytes));
                case "aes256-gcm@openssh.com":
                {
                    byte[] key = kex.DeriveKey(keyLetter, sessionId, AesGcmOpenSshCipher.Aes256KeyBytes);
                    byte[] iv = kex.DeriveKey(ivLetter, sessionId, AesGcmOpenSshCipher.IvMaterialBytes);
                    return new AesGcmOpenSshCipher(key, iv);
                }
                default: throw new System.NotSupportedException(name);
            }
        }

        async Task<byte[]> ReadExpectingAsync(SshMessageNumber expected, CancellationToken cancellationToken)
        {
            while (true)
            {
                byte[] msg = await _codec!.ReadPacketAsync(cancellationToken);
                if (msg.Length == 0) continue;
                if ((SshMessageNumber)msg[0] == expected) return msg;
            }
        }

        async Task<(string clientId, byte[] leftover)> ReadClientIdAsync(CancellationToken cancellationToken)
        {
            var line = new System.Collections.Generic.List<byte>();
            var over = new System.Collections.Generic.List<byte>();
            byte[] one = new byte[256];
            while (true)
            {
                int read = await _stream.ReadAsync(one.AsMemory(), cancellationToken);
                for (int i = 0; i < read; i++)
                {
                    byte b = one[i];
                    if (b == (byte)'\n')
                    {
                        if (line.Count > 0 && line[line.Count - 1] == (byte)'\r') line.RemoveAt(line.Count - 1);
                        string text = System.Text.Encoding.ASCII.GetString(line.ToArray());
                        if (text.StartsWith("SSH-"))
                        {
                            for (int j = i + 1; j < read; j++) over.Add(one[j]);
                            return (text, over.ToArray());
                        }
                        line.Clear();
                    }
                    else line.Add(b);
                }
            }
        }

        // The server-side KDF: reuse Curve25519KeyExchange's derive logic by re-encoding the mpint here.
        sealed class ServerKex
        {
            readonly byte[] _kMpint;
            readonly byte[] _h;
            public ServerKex(byte[] shared, byte[] exchangeHash)
            {
                var w = new SshWriter();
                w.WriteMpint(shared);
                _kMpint = w.ToArray();
                _h = exchangeHash;
            }

            public byte[] DeriveKey(char letter, byte[] sessionId, int length)
            {
                using var sha = System.Security.Cryptography.SHA256.Create();
                byte[] k1 = sha.ComputeHash(Concat(_kMpint, _h, new[] { (byte)letter }, sessionId));
                var output = new System.Collections.Generic.List<byte>(k1);
                while (output.Count < length)
                {
                    byte[] next = sha.ComputeHash(Concat(_kMpint, _h, output.ToArray()));
                    output.AddRange(next);
                }
                return output.GetRange(0, length).ToArray();
            }

            static byte[] Concat(params byte[][] parts)
            {
                int total = 0; foreach (var p in parts) total += p.Length;
                byte[] result = new byte[total]; int off = 0;
                foreach (var p in parts) { System.Buffer.BlockCopy(p, 0, result, off, p.Length); off += p.Length; }
                return result;
            }
        }
    }
}
