using System.Security.Cryptography;

namespace AuthShield
{
    public class PasswordManager
    {
        private const int SaltSize = 16; // Size of salt in bytes
        private const int HashSize = 32; // Size of hash in bytes
        private const int Iterations = 10000; // Number of iterations for PBKDF2

        public static string GenerateSaltedHash(string password)
        {
            // Generate a random salt
            var salt = new byte[SaltSize];
            RandomNumberGenerator.Fill(salt);

            // Generate the hash using PBKDF2
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
            {
                var hash = pbkdf2.GetBytes(HashSize);

                // Combine salt and hash into one byte array
                var hashBytes = new byte[SaltSize + HashSize];
                Array.Copy(salt, 0, hashBytes, 0, SaltSize);
                Array.Copy(hash, 0, hashBytes, SaltSize, HashSize);

                // Return the combined hash and salt as a Base64 encoded string
                return Convert.ToBase64String(hashBytes);
            }
        }

        public static bool VerifyPassword(string password, string hashedPassword)
        {
            // Extract the salt and hash from the Base64 encoded string
            var hashBytes = Convert.FromBase64String(hashedPassword);
            var salt = new byte[SaltSize];
            var hash = new byte[HashSize];
            Array.Copy(hashBytes, 0, salt, 0, SaltSize);
            Array.Copy(hashBytes, SaltSize, hash, 0, HashSize);

            // Hash the input password with the extracted salt
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
            {
                var testHash = pbkdf2.GetBytes(HashSize);

                // Compare the hashes
                return testHash.AsSpan().SequenceEqual(hash);
            }
        }
    }
}