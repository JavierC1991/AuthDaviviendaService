using System.Security.Cryptography;
using System.Text;

namespace AuthServiceDavivienda
{
    public class Seguridad
    {
        //Variables para cifrado de la contraseña
        private static string palapaso = "WS_CAP";
        private static string valorSalt = "WS_CAP_2022";
        private static string encrip = "SHA1";
        private static string vector = "1234567891234567";
        private static int ite = 22;
        private static int tam_clave = 256;

        //Encriptar
        public static string EncodeHash(string textoCifrar)
        {
            try
            {
                byte[] InitialVectorBytes = Encoding.ASCII.GetBytes(vector);
                byte[] saltValueBytes = Encoding.ASCII.GetBytes(valorSalt);
                byte[] plainTextBytes = Encoding.UTF8.GetBytes(textoCifrar);

                PasswordDeriveBytes password =
                    new PasswordDeriveBytes(palapaso, saltValueBytes,
                        encrip, ite);
                byte[] keyBytes = password.GetBytes(tam_clave / 8);
                RijndaelManaged symmetricKey = new RijndaelManaged();
                symmetricKey.Mode = CipherMode.CBC;
                ICryptoTransform encryptor =
                    symmetricKey.CreateEncryptor(keyBytes, InitialVectorBytes);
                MemoryStream memoryStream = new MemoryStream();
                CryptoStream cryptoStream =
                    new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                cryptoStream.FlushFinalBlock();
                byte[] cipherTextBytes = memoryStream.ToArray();
                memoryStream.Close();
                cryptoStream.Close();
                string textoCifradoFinal = Convert.ToBase64String(cipherTextBytes);
                return textoCifradoFinal;
            }
            catch
            {
                return "";
            }
        }
    }
}
