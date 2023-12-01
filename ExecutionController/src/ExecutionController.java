import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class ExecutionController {
    private final String appName;
    private final String version;
    private KeyPair keyPair;
    public ExecutionController(String appName, String version) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        this.appName = appName;
        this.version = version;

        //check if there's a key par for the app
        Path keyDir = Paths.get(System.getProperty("user.dir"), "assym_keys");
        if (!Files.isDirectory(keyDir)) {
            Files.createDirectory(keyDir);
        }
        Path publicKeyPath = Paths.get(System.getProperty("user.dir"), "assym_keys", "public_k");
        Path privateKeyPath = Paths.get(System.getProperty("user.dir"), "assym_keys", "private_k");

        if (!Files.exists(publicKeyPath) || !Files.exists(privateKeyPath)) {
            System.out.println("Erro ao econtrar ChavePublica E ChavePrivada");
            //Create a new pair and save it
            int keySize = 2048;
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keySize);
            keyPair = keyPairGenerator.generateKeyPair();

            System.out.println("Novo par de chaves criado!");

            //save to file
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(publicKeyPath.toFile()));
            bos.write(keyPair.getPublic().getEncoded());
            bos.close();

            bos = new BufferedOutputStream(new FileOutputStream(privateKeyPath.toFile()));
            bos.write(keyPair.getPrivate().getEncoded());
            bos.close();

            System.out.printf("Par de chaves guarda com sucesso em:\n%s\n%s\n", publicKeyPath, privateKeyPath);

        } else {
            System.out.println("Encontrado com sucesso par de chaves.");
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyPath);
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);

            //load the pair of keys
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            keyPair = new KeyPair(publicKey, privateKey);
            System.out.println("Par de chaves, carregadas do ficheiro com sucesso.");
        }

    }

    public boolean isRegistered() throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("indique o caminho da diretoria que contêm a licença:");
        Path licenceDirectory = Path.of(scanner.nextLine());

        if (!Files.isDirectory(licenceDirectory)) {
            System.out.println("Não foi possível encontrar a diretoria no caminho indicado!");
            return false;
        }

        Path licencePath = Paths.get(String.valueOf(licenceDirectory), "licence_info");
        Path licenceIVPath = Paths.get(String.valueOf(licenceDirectory), "licence_iv");
        Path licenceKeyPath = Paths.get(String.valueOf(licenceDirectory), "licence_key");

        if (!Files.exists(licencePath) || !Files.exists(licenceIVPath) || !Files.exists(licenceKeyPath)) {
            System.out.println("Na diretoria não se encontram todos os ficheiros");
            return false;
        }

        byte[] licenceKeyBytes = Files.readAllBytes(licenceKeyPath);
        byte[] licenceIVBytes = Files.readAllBytes(licenceIVPath);

        Cipher rsaDecipher = Cipher.getInstance("RSA");
        rsaDecipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        byte[] decryptedLicenceKeyBytes = rsaDecipher.doFinal(licenceKeyBytes);
        byte[] decryptedLicenceIVBytes = rsaDecipher.doFinal(licenceIVBytes);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec licenceKeySpec = new SecretKeySpec(decryptedLicenceKeyBytes, "AES");
        aesCipher.init(Cipher.DECRYPT_MODE, licenceKeySpec, new IvParameterSpec(decryptedLicenceIVBytes));

        byte[] licenceInfo = Files.readAllBytes(licencePath);
        byte[] decryptedLicenceInfo = aesCipher.doFinal(licenceInfo);

        String stringInfo = new String(decryptedLicenceInfo, StandardCharsets.UTF_8);

        System.out.println(stringInfo);
        return true;
    }
    public boolean startRegistration() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException, InvalidKeySpecException {
        //user data - name, email, nic, cc certificate
        String username = "joao";
        String email = "joao@gmail.com";
        String nic = "999888777";
        //system data - cpu nr, cpu type, mac addr
        int cpus = 2;
        String cpuType = "Intel";
        String macAddresses = "555";
        //app data - name, version, hash
        String appName = "protectedApp";
        String version = "1.0";

        //verifica se existe Chave Pública do Autor no lugar esperado
        Path authorPublicKeyPath = Paths.get(System.getProperty("user.dir"), "author_keys", "author_public_key");

        if (!Files.exists(authorPublicKeyPath)) {
            System.out.println("Não foi possível encontrar chave pública do autor");
            return false;
        }

        byte[] authorPublicKeyBytes = Files.readAllBytes(authorPublicKeyPath);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey authorPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(authorPublicKeyBytes));


        byte[] iv = generateIV();
        SecretKey key = generateKey();

        String sb = "%s\n%s\n%s\n%d\n%s\n%s\n%s\n%s".formatted(username, email, nic, cpus, cpuType, macAddresses, appName, version);
        byte[] encryptedData = encrypt(sb, key, iv);

        Path filePath = Paths.get( System.getProperty("user.home"), "licence_request", "licence_request_data");
        System.out.println(filePath);
        Files.createDirectories(filePath.getParent());

        BufferedOutputStream os = new BufferedOutputStream(new FileOutputStream(filePath.toFile()));
        os.write(encryptedData);
        os.close();
        System.out.println("Dados necessários para pedido de licença, guardados com sucesso!");

        //Encriptar Chave
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, authorPublicKey);

        byte[] encryptedKey = rsaCipher.doFinal(key.getEncoded());
        byte[] encryptedIV = rsaCipher.doFinal(iv);

        //Guardar na mesma pasta
        Path encryptedKeyPath = Paths.get(System.getProperty("user.home"), "licence_request", "licence_key");
        Path encryptedIVPath = Paths.get(System.getProperty("user.home"), "licence_request", "licence_iv");

        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(encryptedKeyPath.toFile()));
        bos.write(encryptedKey);
        bos.close();

        bos = new BufferedOutputStream(new FileOutputStream(encryptedIVPath.toFile()));
        bos.write(encryptedIV);
        bos.close();

        Path appPublicKeyPath = Paths.get(System.getProperty("user.home"), "licence_request", "app_public_key");
        bos = new BufferedOutputStream(new FileOutputStream(appPublicKeyPath.toFile()));
        bos.write(keyPair.getPublic().getEncoded());
        bos.close();

        return true;
    }

    public void showLicenceInfo() {

    }

    private byte[] generateIV() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }
    private SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
    private byte[] encrypt(String input, Key key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(input.getBytes());
    }
}
