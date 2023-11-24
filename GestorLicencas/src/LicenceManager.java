import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class LicenceManager {

    public void generateLicence() {
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
        //encrypt()

    }

    private String encrypt(String input, Key key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}
