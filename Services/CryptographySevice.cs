using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

using Sec_Backend.Models;

namespace Sec_Backend.Services
{
    public class CryptographySevice
    {
        private readonly IConfiguration _configuration;
        private readonly IMongoCollection<Users> _user;
        public CryptographySevice(IConfiguration configuration, MongoDbService mongoDbService)
        {
            _configuration = configuration;
            _user = mongoDbService.Database.GetCollection<Users>("users");
        }

        public (string publicKey, string privateKey) GenerateKeyPair()
        {
            using (var rsa = RSA.Create(2048))
            {
                var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                var encryptedPrivateKey = EncryptTextAES(privateKey);
                return (publicKey, encryptedPrivateKey);
            }
        }

        private string EncryptTextAES(string privateKey)
        {
#pragma warning disable CS8604 // Possible null reference argument.
            var key = Convert.FromBase64String(_configuration["EncryptionSettings:Key"]);
            var iv = Convert.FromBase64String(_configuration["EncryptionSettings:IV"]);
#pragma warning restore CS8604 // Possible null reference argument.

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(privateKey);
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        private string DecryptTextAES(string encryptedPrivateKey)
        {
#pragma warning disable CS8604 // Possible null reference argument.
            var key = Convert.FromBase64String(_configuration["EncryptionSettings:Key"]);
            var iv = Convert.FromBase64String(_configuration["EncryptionSettings:IV"]);
#pragma warning restore CS8604 // Possible null reference argument.

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                var cipherBytes = Convert.FromBase64String(encryptedPrivateKey);

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream(cipherBytes))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }


        // Create a digital signature for the audio file using the private key
        public byte[] SignData(byte[] data, string userId)
        {
            var privateKey = GetPrivateKeyForUser(userId);
            var DecryptPrivateKey = DecryptTextAES(privateKey);
            using (var rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(Convert.FromBase64String(DecryptPrivateKey), out _);
                using (var sha256 = SHA256.Create())
                {
                    var hash = sha256.ComputeHash(data);
                    return rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
        }

        // Verify the digital signature using the public key
        public bool VerifySignature(byte[] data, byte[] signature, string userId)
        {
            var publicKey = GetPublicKeyForUser(userId);
            using (var rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
                using (var sha256 = SHA256.Create())
                {
                    var hash = sha256.ComputeHash(data);
                    return rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
        }

        private string GetPublicKeyForUser(string userId)
        {
            // Find user in the database
            var user = _user.Find(u => u.id == userId).FirstOrDefault();

            if (user == null || string.IsNullOrEmpty(user.publicKey))
            {
                throw new Exception("Public key not found for user.");
            }

            // Return the public key as string (XML format)
            return user.publicKey;
        }

        private string GetPrivateKeyForUser(string userId)
        {
            // Find user in the database
            var user = _user.Find(u => u.id == userId).FirstOrDefault();

            if (user == null || string.IsNullOrEmpty(user.privateKey))
            {
                throw new Exception("Public key not found for user.");
            }

            // Return the public key as string (XML format)
            return user.privateKey;
        }

        // Generate JWT Token
        public string GenerateJwtToken(Users user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user), "User cannot be null.");
            }

            if (string.IsNullOrEmpty(user.id))
            {
                throw new ArgumentException("User ID cannot be null or empty.", nameof(user.id));
            }

            if (string.IsNullOrEmpty(user.email))
            {
                throw new ArgumentException("User Email cannot be null or empty.", nameof(user.email));
            }

            if (string.IsNullOrEmpty(user.username))
            {
                throw new ArgumentException("User Username cannot be null or empty.", nameof(user.username));
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var secretKey = _configuration["Jwt:SecretKey"];
            if (string.IsNullOrEmpty(secretKey))
            {
                throw new InvalidOperationException("JWT SecretKey is not configured.");
            }

            var key = Encoding.ASCII.GetBytes(secretKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
            new Claim(ClaimTypes.NameIdentifier, user.id),
            new Claim(ClaimTypes.Email, user.email),
            new Claim(ClaimTypes.Name, user.username)
        }),
                Expires = DateTime.UtcNow.AddHours(48),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public string EncryptPathBlowfish(string path)
        {
#pragma warning disable CS8604 // Possible null reference argument.
            byte[] key = Convert.FromBase64String(_configuration["BlowfishSettings:Key"]);
#pragma warning restore CS8604 // Possible null reference argument.
            IBufferedCipher cipher = CipherUtilities.GetCipher("Blowfish/ECB/PKCS7");
            cipher.Init(true, new KeyParameter(key));

            byte[] inputBytes = Encoding.UTF8.GetBytes(path);
            byte[] outputBytes = cipher.DoFinal(inputBytes);

            return Convert.ToBase64String(outputBytes);
        }

        public string DecryptPathBlowfish(string encryptedPath)
        {
#pragma warning disable CS8604 // Possible null reference argument.
            byte[] key = Convert.FromBase64String(_configuration["BlowfishSettings:Key"]);
#pragma warning restore CS8604 // Possible null reference argument.
            IBufferedCipher cipher = CipherUtilities.GetCipher("Blowfish/ECB/PKCS7");
            cipher.Init(false, new KeyParameter(key));

            byte[] inputBytes = Convert.FromBase64String(encryptedPath);
            byte[] outputBytes = cipher.DoFinal(inputBytes);

            return Encoding.UTF8.GetString(outputBytes);
        }

        public byte[] EncryptAudioAES(byte[] audioBytes)
        {
#pragma warning disable CS8604 // Possible null reference argument.
            var key = Convert.FromBase64String(_configuration["EncryptionSettings:Key"]);
            var iv = Convert.FromBase64String(_configuration["EncryptionSettings:IV"]);
#pragma warning restore CS8604 // Possible null reference argument.
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            csEncrypt.Write(audioBytes, 0, audioBytes.Length);
                            csEncrypt.FlushFinalBlock();
                            return msEncrypt.ToArray();
                        }
                    }
                }
            }
        }

        public byte[] DecryptAudioAES(byte[] encryptedAudioBytes)
        {
#pragma warning disable CS8604 // Possible null reference argument.
            byte[] key = Convert.FromBase64String(_configuration["EncryptionSettings:Key"]);
            byte[] iv = Convert.FromBase64String(_configuration["EncryptionSettings:IV"]);
#pragma warning restore CS8604 // Possible null reference argument.

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (var msDecrypt = new MemoryStream(encryptedAudioBytes))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var msResult = new MemoryStream())
                            {
                                csDecrypt.CopyTo(msResult);
                                return msResult.ToArray();
                            }
                        }
                    }
                }
            }
        }

        private byte[] SHA256Hash(byte[] input)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(input); // คืนค่าเป็น byte[]
            }
        }

    }
}