import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Base64;

public class LicenceManager {

    public void generateLicence() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
            IOException {
        //user data (temp)
        String userName = "Joao";
        String userEmail = "joao@gmail.com";
        int civilIdNumber = 5;
        //system data (temp)
        int serialNumber = 10;
        //app data (temp)
        String appName = "protectedApp";
        String appVersion = "1.0";
        //licence duration data (temp)
        String issueDate = "24/11/2023";
        String expiryDate = "30/11/2023";

        //encryption
        SecretKey key = generateKey();
        byte[] iv = generateIV();
        encrypt(appName, key, iv);

        //save to file
        String fileName = "licenceTest";
        saveToFile(encrypt(appName, key, iv), fileName);
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

    private void saveToFile(byte[] data, String fileName) throws IOException {
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(data);
        fos.close();
    }
}
