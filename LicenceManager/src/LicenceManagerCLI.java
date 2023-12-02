import org.bouncycastle.operator.OperatorCreationException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class LicenceManagerCLI {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException, InvalidKeySpecException, UnrecoverableEntryException, CertificateException, KeyStoreException, OperatorCreationException {
        Scanner scanner = new Scanner(System.in);
        boolean exit = false;

        LicenceManager lm = new LicenceManager();

        while (!exit) {
            System.out.println("Menu:");
            System.out.println("1. Criar licença");
            System.out.println("2. Criar par de chaves");
            System.out.println("3. Listar licenças");
            System.out.println("0. Sair");

            int op = scanner.nextInt();
            scanner.nextLine();

            switch (op) {
                case 0: //sair
                    exit = true;
                    break;
                case 1: //criar licença
                    //Verificar se existe ficheiros para as chaves (pública e privada)
                    Path privateKeyPath = Paths.get(System.getProperty("user.dir"), "keys", "private_key");
                    Path publicKeyPath = Paths.get(System.getProperty("user.dir"), "keys", "public_key");

                    if (!Files.exists(privateKeyPath) || !Files.exists(publicKeyPath)) {
                        System.out.println("Não foi possível encontrar o par de chaves do autor");
                        break;
                    }

                    System.out.println("Indique o caminho para o pedido de licença");
                    Path licenceRequestPath = Paths.get(scanner.nextLine().trim());

                    if (!Files.isDirectory(licenceRequestPath)) {
                        System.out.println("Não existe diretoria no caminho indicado");
                        break;
                    }

                    Path licenceKeyPath = licenceRequestPath.resolve("licence_key");
                    Path licenceIVPath = licenceRequestPath.resolve("licence_iv");
                    Path licenceDataPath = licenceRequestPath.resolve("licence_request_data");
                    Path appPublicKeyPath = licenceRequestPath.resolve("app_public_key");

                    if (!Files.exists(licenceKeyPath) || !Files.exists(licenceIVPath) || !Files.exists(licenceDataPath) || !Files.exists(appPublicKeyPath)) {
                        System.out.println("Diretoria de pedido de licença não tem todos os ficheiros necessários");
                    }

                    //Desencriptar Chave e IV do pedido
                    // todo verificar se a instância LM tem valores da chave
                    Cipher rsaDecipher = Cipher.getInstance("RSA");
                    rsaDecipher.init(Cipher.DECRYPT_MODE, lm.getPrivateKey());

                    byte[] licenceKeyBytes = Files.readAllBytes(licenceKeyPath);
                    byte[] licenceIVBytes = Files.readAllBytes(licenceIVPath);

                    byte[] decryptedLicenceKey = rsaDecipher.doFinal(licenceKeyBytes);
                    byte[] decryptedLicenceIV = rsaDecipher.doFinal(licenceIVBytes);

                    SecretKeySpec licenceKey = new SecretKeySpec(decryptedLicenceKey, "AES");
                    IvParameterSpec licenceIV = new IvParameterSpec(decryptedLicenceIV);

                    Cipher aesDecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    aesDecipher.init(Cipher.DECRYPT_MODE, licenceKey, licenceIV);

                    byte[] licenceRequestDataBytes = Files.readAllBytes(licenceDataPath);
                    byte[] decryptedLicenceRequestData = aesDecipher.doFinal(licenceRequestDataBytes);

                    String licenceInfo = new String(decryptedLicenceRequestData);
                    System.out.println(licenceInfo);

                    byte[] appPublicKeyBytes = Files.readAllBytes(appPublicKeyPath);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey appPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(appPublicKeyBytes));
                    //todo criar nova licença
                    lm.generateLicence(licenceInfo, appPublicKey);
                    break;
                case 2: //criar par de chaves
                    lm.generateKeyPair();
                    break;
                case 3: //listar licenças
                    break;
            }
        }

        scanner.close();
    }
}
