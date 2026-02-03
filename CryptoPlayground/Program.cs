using System;
using Core;

class Program
{
    static void Main()
    {
        using var bob = new DmV0.DeviceKeys("bobDevice1");
        var bobbundle = bob.ExportBundle();

        var (init, aliceSession) = DmV0.Initiate("aliceDevice1", bobbundle);
        using var bobSession = DmV0.Respond(bob, init);

        var m1 = aliceSession.Encrypt("alice to bob");
        PrintEncrypted("alice to bob (encrypted)", m1);

        var bobPlain1 = bobSession.Decrypt(m1);
        Console.WriteLine("bob decrypted: " + bobPlain1);
        Console.WriteLine();

        var m2 = bobSession.Encrypt("bob to alice");
        PrintEncrypted("bob to alice (encrypted)", m2);

        var alicePlain2 = aliceSession.Decrypt(m2);
        Console.WriteLine("alice decrypted: " + alicePlain2);
        Console.WriteLine();

        // show that a random session cant decrypt it
        using var eve = new DmV0.DeviceKeys("eveDevice1");
        var (eveInit, eveSession) = DmV0.Initiate("eveDevice1", bobbundle); // different shared keys
        try
        {
            Console.WriteLine("eve tries to decrypt alice-bob...");
            Console.WriteLine(eveSession.Decrypt(m1));
        }
        catch (Exception ex)
        {
            Console.WriteLine("eve failed (as intended): " + ex.GetType().Name + " - " + ex.Message);
        }
    }

    static void PrintEncrypted(string label, DmV0.EncryptedMessage msg)
    {
        Console.WriteLine(label);
        Console.WriteLine("  conversationId16: " + Hex(msg.ConversationId16));
        Console.WriteLine("  counter:          " + msg.Counter);
        Console.WriteLine("  nonce24:          " + Hex(msg.Nonce24));
        Console.WriteLine("  ciphertext:       " + Hex(msg.Ciphertext));
        Console.WriteLine("  ciphertext bytes: " + msg.Ciphertext.Length);
        Console.WriteLine();
    }

    static string Hex(byte[] bytes) => Convert.ToHexString(bytes);
}
