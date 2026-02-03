using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace Core;

// one handshake + two directional keys + aead per message
// upgrade to doubel rachet later
public static class DmV0
{
    private static readonly SignatureAlgorithm SigAlg = SignatureAlgorithm.Ed25519;
    private static readonly KeyAgreementAlgorithm DhAlg = KeyAgreementAlgorithm.X25519;
    private static readonly KeyDerivationAlgorithm Kdf = KeyDerivationAlgorithm.HkdfSha256;
    private static readonly AeadAlgorithm Aead = AeadAlgorithm.XChaCha20Poly1305;

    public sealed record PreKeyBundle(
        string DeviceId,
        byte[] IdentityPubEd25519,
        byte[] SignedPreKeyPubX25519,
        byte[] SignedPreKeySignature 
    );

    public sealed record HandshakeInit(
        string InitiatorDeviceId,
        byte[] InitiatorEphPubX25519,
        byte[] Salt32,
        byte[] ConversationId16
    );

    public sealed record EncryptedMessage(
        byte[] ConversationId16,
        ulong Counter,
        byte[] Nonce24,
        byte[] Ciphertext
    );

    public sealed class DeviceKeys : IDisposable
    {
        public string DeviceId { get; }
        public Key IdentityKeyEd25519 { get; }
        public Key SignedPreKeyX25519 { get; }

        public DeviceKeys(string deviceId)
        {
            DeviceId = deviceId;

            IdentityKeyEd25519 = Key.Create(SigAlg);
            SignedPreKeyX25519 = Key.Create(DhAlg);
        }

        public PreKeyBundle ExportBundle()
        {
            var identityPub = IdentityKeyEd25519.PublicKey.Export(KeyBlobFormat.RawPublicKey);
            var spkPub = SignedPreKeyX25519.PublicKey.Export(KeyBlobFormat.RawPublicKey);

            var toSign = Concat(Encoding.UTF8.GetBytes(DeviceId), spkPub);
            var sig = SigAlg.Sign(IdentityKeyEd25519, toSign);

            return new PreKeyBundle(DeviceId, identityPub, spkPub, sig);
        }

        public void Dispose()
        {
            IdentityKeyEd25519.Dispose();
            SignedPreKeyX25519.Dispose();
        }
    }

    public sealed class Session : IDisposable
    {
        public byte[] ConversationId16 { get; }
        private readonly Key _sendKey;
        private readonly Key _recvKey;

        public ulong SendCounter { get; private set; }
        public ulong RecvCounter { get; private set; }

        public Session(byte[] conversationId16, Key sendKey, Key recvKey)
        {
            ConversationId16 = conversationId16;
            _sendKey = sendKey;
            _recvKey = recvKey;
        }

        public EncryptedMessage Encrypt(string plaintext)
        {
            var pt = Encoding.UTF8.GetBytes(plaintext);

            byte[] nonce = new byte[Aead.NonceSize];
            RandomNumberGenerator.Fill(nonce);

            var counter = ++SendCounter;
            var ad = BuildAssociatedData(ConversationId16, counter);

            byte[] ct = new byte[pt.Length + Aead.TagSize];
            Aead.Encrypt(_sendKey, nonce, ad, pt, ct);

            return new EncryptedMessage(ConversationId16, counter, nonce, ct);
        }

        public string Decrypt(EncryptedMessage msg)
        {
            if (!msg.ConversationId16.SequenceEqual(ConversationId16))
                throw new CryptographicException("incorrect conversation id");

            if (msg.Counter <= RecvCounter)
                throw new CryptographicException("replat and Out of Order arent supported yet :(");

            var ad = BuildAssociatedData(msg.ConversationId16, msg.Counter);

            byte[] pt = new byte[msg.Ciphertext.Length - Aead.TagSize];
            Aead.Decrypt(_recvKey, msg.Nonce24, ad, msg.Ciphertext, pt);

            RecvCounter = msg.Counter;
            return Encoding.UTF8.GetString(pt);
        }

        public void Dispose()
        {
            _sendKey.Dispose();
            _recvKey.Dispose();
        }
    }

    // alice starts a dm with bob’s published 'bundle'
    // returns handshake init to send, alice session, alice eph private key kept inside via closure
    public static (HandshakeInit init, Session aliceSession) Initiate(
        string aliceDeviceId,
        PreKeyBundle bobBundle)
    {
        VerifyBundleOrThrow(bobBundle);

        // alice ephemeral X25whatever
        using var aliceEph = Key.Create(DhAlg);
        var aliceEphPub = aliceEph.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        // bob signed prekey pub
        var bobSpkPub = PublicKey.Import(DhAlg, bobBundle.SignedPreKeyPubX25519, KeyBlobFormat.RawPublicKey);

        // DH shared secret
        using var shared = DhAlg.Agree(aliceEph, bobSpkPub)
            ?? throw new CryptographicException("DH agreement failed.");

        // i should make my own RNG so its not guessable blah blah blah
        byte[] salt = new byte[32];
        RandomNumberGenerator.Fill(salt);

        byte[] convoId = MakeConversationId16(aliceEphPub, bobBundle.SignedPreKeyPubX25519, salt);

        var init = new HandshakeInit(aliceDeviceId, aliceEphPub, salt, convoId);

        var baseInfo = BuildKdfInfo(aliceEphPub, bobBundle.SignedPreKeyPubX25519, bobBundle.DeviceId);
        var sendKey = DeriveAeadKey(shared, salt, baseInfo, "i2r");
        var recvKey = DeriveAeadKey(shared, salt, baseInfo, "r2i");

        var aliceSession = new Session(convoId, sendKey, recvKey);
        return (init, aliceSession);
    }

      public static Session Respond(
        DeviceKeys bobKeys,
        HandshakeInit init)
    {
        // yes i actually named this stuff alice and bob
        var aliceEphPub = PublicKey.Import(DhAlg, init.InitiatorEphPubX25519, KeyBlobFormat.RawPublicKey);

        using var shared = DhAlg.Agree(bobKeys.SignedPreKeyX25519, aliceEphPub)
            ?? throw new CryptographicException("dh agreement failed");

        var bobSpkPub = bobKeys.SignedPreKeyX25519.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        var baseInfo = BuildKdfInfo(init.InitiatorEphPubX25519, bobSpkPub, bobKeys.DeviceId);

        var sendKey = DeriveAeadKey(shared, init.Salt32, baseInfo, "r2i");
        var recvKey = DeriveAeadKey(shared, init.Salt32, baseInfo, "i2r");
        var expectedConvo = MakeConversationId16(init.InitiatorEphPubX25519, bobSpkPub, init.Salt32);
        if (!expectedConvo.SequenceEqual(init.ConversationId16))
            throw new CryptographicException("conversation id mismatch");

        return new Session(init.ConversationId16, sendKey, recvKey);
    }

    private static void VerifyBundleOrThrow(PreKeyBundle b)
    {
        var identityPub = PublicKey.Import(SigAlg, b.IdentityPubEd25519, KeyBlobFormat.RawPublicKey);
        var toVerify = Concat(Encoding.UTF8.GetBytes(b.DeviceId), b.SignedPreKeyPubX25519);

        if (!SigAlg.Verify(identityPub, toVerify, b.SignedPreKeySignature))
            throw new CryptographicException("invalid or outdated bundle sig");
    }

    private static Key DeriveAeadKey(SharedSecret shared, byte[] salt, byte[] baseInfo, string direction)
    {
        var info = Concat(baseInfo, Encoding.UTF8.GetBytes("|" + direction));
        var okm = Kdf.DeriveBytes(shared, salt, info, 32); // is 32 enough
        return Key.Import(Aead, okm, KeyBlobFormat.RawSymmetricKey);
    }
    private static byte[] BuildAssociatedData(byte[] convoId16, ulong counter)
    {
        var counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(counterBytes);
        return Concat(convoId16, counterBytes);
    }

    private static byte[] BuildKdfInfo(byte[] aliceEphPub, byte[] bobSpkPub, string bobDeviceId)
    {
        return Concat(
            Encoding.UTF8.GetBytes("convonyx|dm-v0|"),
            Encoding.UTF8.GetBytes("bobDevice=" + bobDeviceId + "|"),
            aliceEphPub,
            bobSpkPub
        );
    }

    private static byte[] MakeConversationId16(byte[] aliceEphPub, byte[] bobSpkPub, byte[] salt)
    {
        var full = SHA256.HashData(Concat(aliceEphPub, bobSpkPub, salt));
        return full.Take(16).ToArray();
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var len = parts.Sum(p => p.Length);
        var outBytes = new byte[len];
        int off = 0;
        foreach (var p in parts)
        {
            Buffer.BlockCopy(p, 0, outBytes, off, p.Length);
            off += p.Length;
        }
        return outBytes;
    }
}
