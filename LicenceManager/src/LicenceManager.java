import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;

public class LicenceManager {
    private KeyPair keyPair;

    public LicenceManager() {

    }

    public byte[] getPublicKey() {
        return keyPair.getPublic().getEncoded();
    }

    public void generateLicence() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        //user data
        String username = "Joao";
        String email = "joao@gmail.com";
        int civilID = 5;
        //system data
        int serial = 10;
        String appName = "exampleApp";
        String appVersion = "1.0";
        //licence duration data
        String issueDate = "24/11/2023";
        String expiryDate = "30/11/2023";

        //encryption
        SecretKey key = generateKey();
        byte[] iv = generateIV();
        byte[] encryptedData = encrypt(appName, key, iv);

        //save to file
        String fileName = "licenceTest";
        Path filePath = Paths.get(System.getProperty("user.dir"), "licences", fileName);
        saveToFile(encryptedData, filePath);
    }
    public void generateKeyPair() throws NoSuchAlgorithmException {
        int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        keyPair = keyPairGenerator.generateKeyPair();
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

    private void saveToFile(byte[] data, Path path) throws IOException {
        Files.createDirectories(path.getParent());
        FileOutputStream fos = new FileOutputStream(path.toFile());
        fos.write(data);
        fos.close();
    }
}
