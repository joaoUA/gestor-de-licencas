import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Scanner;

public class ExecutionController {
    private String appName;
    private String version;
    public ExecutionController(String appName, String version) {
        this.appName = appName;
        this.version = version;
    }

    public boolean isRegistered() {
        return false;
    }
    public boolean startRegistration() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        //user data - name, email, nic, cc certificate
        String username;
        String email;
        String nic;
        //system data - cpu nr, cpu type, mac addr
        int cpus;
        String cpuType;
        String macAddresses;
        //app data - name, version, hash
        String appName;
        String version;

        Scanner scanner = new Scanner(System.in);

        System.out.println("Processo de criação de pedido de licença");
        do {
            System.out.println("Enter your name:");
            username = scanner.nextLine();
        } while (username.isEmpty());

        do {
            System.out.println("Enter your email:");
            email = scanner.nextLine();
        } while (email.isEmpty());

        do {
            System.out.println("Enter your nic");
            nic = scanner.nextLine();
        } while (nic.isEmpty());

        do {
            System.out.println("Enter the number of CPUs:");
            cpus = scanner.nextInt();
            scanner.nextLine();
        } while (cpus < 1);

        do {
            System.out.println("Enter the type of CPUs:");
            cpuType = scanner.nextLine();
        } while (cpuType.isEmpty());

        do {
            System.out.println("Enter the MAC Addresses:");
            macAddresses = scanner.nextLine();
        } while (macAddresses.isEmpty());

        do {
            System.out.println("Enter the app's name:");
            appName = scanner.nextLine();
        } while (appName.isEmpty());

        do {
            System.out.println("Enter the app's current version:");
            version = scanner.nextLine();
        } while (version.isEmpty());

        /*
        todo encriptar dados com cifra simétrica (AES/CBC)
            encriptar chave & iv resultante, com cifra assimétrica (RSA, e chave pública do autor)
            colocar tudo numa pasta para ser enviado para o autor
        */

        byte[] iv = generateIV();
        SecretKey key = generateKey();
        encrypt(appName, key, iv);

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
