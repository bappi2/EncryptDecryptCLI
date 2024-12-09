// C# AES encryption and decryption - Cyber Security in C#
// https://www.youtube.com/watch?v=KykVuOvFfZU&ab_channel=tutorialsEU-C%23
// https://tutorials.eu/cyber-security-with-csharp/

using System.Security.Cryptography;


    Console.WriteLine("Please enter a username:");
    string username = Console.ReadLine();
    Console.WriteLine("Please enter a password:");
    string password = Console.ReadLine();
    // Generate a key and IV
    
    byte[] key = new byte[32];
    byte[] iv = new byte[16];
    
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(key);
        rng.GetBytes(iv);
    }
    // Encrypt the password
    byte[] encryptedPassword = EncryptString(password, key, iv);
    string encryptedPasswordString = Convert.ToBase64String(encryptedPassword);
    Console.WriteLine("encrypted password: " + encryptedPasswordString);
    
    // Decrypt the password
    string decryptedPassword = DecryptString(encryptedPassword, key, iv);
    Console.WriteLine("decrypted password: " + decryptedPassword);
    Console.ReadLine();
    return;

static string DecryptString(byte[] cipheredtext, byte[] key, byte[] iv)
{
    using Aes aes = Aes.Create();
    aes.Key = key;
    aes.IV = iv;
    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
    using MemoryStream ms = new MemoryStream(cipheredtext);
    using CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
    using StreamReader reader = new StreamReader(cs);
    return reader.ReadToEnd();
}

static byte[] EncryptString(string simpletext, byte[] key, byte[] iv)
{
    byte[] cipheredText;
    using (Aes aes = Aes.Create())
    {
        aes.Key = key;
        aes.IV = iv;
        ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using (MemoryStream ms = new MemoryStream())
        {
            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                using (StreamWriter writer = new StreamWriter(cs))
                {
                    writer.Write(simpletext);
                }
                cipheredText = ms.ToArray();
            }
        }
    }
    return cipheredText;
    
}