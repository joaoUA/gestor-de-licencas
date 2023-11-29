import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class LicenceManager {
    private KeyPair keyPair;
    private String keysFolderName = "keys";
    private String publicKeyFileName = "public_key";
    private String privateKeyFileName = "private_key";
    private Path publicKeyPath;
    private Path privateKeyPath;

    public LicenceManager() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        publicKeyPath = Paths.get(System.getProperty("user.dir"), keysFolderName, publicKeyFileName);
        privateKeyPath = Paths.get(System.getProperty("user.dir"), keysFolderName, privateKeyFileName);

        //Se existir ficheiros das chaves, carregar info
        boolean privateKeyFileFound = Files.exists(privateKeyPath);
        boolean publicKeyFileFound = Files.exists(publicKeyPath);

        if (!privateKeyFileFound) {
            System.out.println("Chave privada do distribuidor não encontrada!");
            System.out.printf("Esperado encontrar chave em: %s\n", privateKeyPath);
        }
        if (!publicKeyFileFound) {
            System.out.println("Chave públic do distribuidor não encontrada!");
            System.out.printf("Esperado encontrar chave em: %s\n", publicKeyPath);
        }
        if (!privateKeyFileFound || !publicKeyFileFound) {
            System.out.println("Crie um novo par de chaves, ou forneça os ficheiros que faltam para o caminho indicado");
            return;
        }

        System.out.println("Chaves do distribuidor encontradas com sucesso!");
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyPath);
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        keyPair = new KeyPair(publicKey, privateKey);


        System.out.println("Chaves do distribuidor carregadas com sucesso!");

    }

    public byte[] getPublicKey() {
        return keyPair.getPublic().getEncoded();
    }
    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public void generateLicence(String licenceInfo, PublicKey appPublicKey) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        //encryption
        SecretKey key = generateKey();
        byte[] iv = generateIV();
        byte[] encryptedData = encrypt(licenceInfo, key, iv);

        //save to file
        String fileName = "licence_info";
        Path filePath = Paths.get(System.getProperty("user.dir"), "licences", "user", fileName);
        saveToFile(encryptedData, filePath, false);

        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, appPublicKey);

        byte[] encryptedKey = rsaCipher.doFinal(key.getEncoded());
        byte[] encryptedIV = rsaCipher.doFinal(iv);

        Path encryptedKeyFile = Paths.get(System.getProperty("user.dir"), "licences", "user", "licence_key");
        Path encryptedIVFile = Paths.get(System.getProperty("user.dir"), "licences", "user", "licence_iv");

        saveToFile(encryptedKey, encryptedKeyFile, false);
        saveToFile(encryptedIV, encryptedIVFile, false);
    }
    public void generateKeyPair() throws NoSuchAlgorithmException, IOException {
        int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        keyPair = keyPairGenerator.generateKeyPair();

        //save to file
        Files.createDirectories(publicKeyPath.getParent());
        Files.createDirectories(privateKeyPath.getParent());

        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(publicKeyPath.toFile()));
        bos.write(keyPair.getPublic().getEncoded());
        bos.close();

        bos = new BufferedOutputStream(new FileOutputStream(privateKeyPath.toFile()));
        bos.write(keyPair.getPrivate().getEncoded());
        bos.close();

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

    private void saveToFile(byte[] data, Path path, boolean append) throws IOException {
        Files.createDirectories(path.getParent());
        FileOutputStream fos = new FileOutputStream(path.toFile(), append);
        fos.write(data);
        fos.close();
    }
}
