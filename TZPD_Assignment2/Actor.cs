using Core.Security.Cryptography;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace TZPD_Assignment2;

public class Actor
{
    public AsymmetricKeyParameter PublicKey { get; }
    private AsymmetricKeyParameter PrivateKey { get; }

    private const string EncryptionAlgorithm = "RSA/ECB/OAEPWithSHA256AndMGF1Padding";
    private const int DefaultRsaBlockSize = 256;

    public Actor()
    {
        var keyPair = GenerateKeys();
        PublicKey = keyPair.Public;
        PrivateKey = keyPair.Private;
    }

    public IEnumerable<byte> Encrypt(AsymmetricKeyParameter publicKey, byte[] dataToEncrypt)
    {
        var cipher = CipherUtilities.GetCipher(EncryptionAlgorithm);
        cipher.Init(true, publicKey);
        return ApplyCipher(dataToEncrypt, cipher, DefaultRsaBlockSize);
    }

    public byte[] Hash(byte[] dataToHash, int hashLength)
    {
        using var hashAlgorithm = new Shake256Managed(hashLength);
        var hashedData = hashAlgorithm.ComputeHash(dataToHash);

        return hashedData;
    }

    public byte[] Sign(byte[] dataToSign)
    {
        var digest = new ShakeDigest(DefaultRsaBlockSize);
        digest.BlockUpdate(dataToSign, 0, dataToSign.Length);

        var signer = new RsaDigestSigner(digest, NistObjectIdentifiers.IdShake256);
        signer.Init(true, PrivateKey);
        signer.BlockUpdate(dataToSign, 0, dataToSign.Length);

        return signer.GenerateSignature();
    }

    public bool VerifySignature(AsymmetricKeyParameter publicKey, byte[] signedData, byte[] signature)
    {
        var digest = new ShakeDigest(DefaultRsaBlockSize);
        digest.BlockUpdate(signedData, 0, signedData.Length);

        var signer = new RsaDigestSigner(digest, NistObjectIdentifiers.IdShake256);
        signer.Init(false, publicKey);
        signer.BlockUpdate(signedData, 0, signedData.Length);

        return signer.VerifySignature(signature);
    }

    public IEnumerable<byte> DecryptData(byte[] encryptedData)
    {
        var cipher = CipherUtilities.GetCipher(EncryptionAlgorithm);
        cipher.Init(false, PrivateKey);

        return ApplyCipher(encryptedData, cipher, DefaultRsaBlockSize);
    }

    private AsymmetricCipherKeyPair GenerateKeys()
    {
        var random = new SecureRandom();
        var keyGenerationParameters = new KeyGenerationParameters(random, 2048);
        var generator = new RsaKeyPairGenerator();
        generator.Init(keyGenerationParameters);

        return generator.GenerateKeyPair();
    }

    private IEnumerable<byte> ApplyCipher(byte[] data, IBufferedCipher cipher, int blockSize)
    {
        var inputStream = new MemoryStream(data);
        var outputBytes = new List<byte>();

        int index;
        var buffer = new byte[blockSize];
        while ((index = inputStream.Read(buffer, 0, blockSize)) > 0)
        {
            var cipherBlock = cipher.DoFinal(buffer, 0, index);
            outputBytes.AddRange(cipherBlock);
        }

        return outputBytes.ToArray();
    }
}