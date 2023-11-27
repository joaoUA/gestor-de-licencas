import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Scanner;

public class ControloExecucao {

    public ControloExecucao(String appName, String version) {

    }

    boolean isRegistered() {
        /*
        todo:  verificar se existe algum ficheiro de licença
            se sim, verificar validade
            desencriptar dados, etc
        */
        return false;
    }

    boolean startRegistration() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        //User Data - name, email, nic, cc certificate
        String userName;
        String userEmail;
        String userNIC;
        //System Data - nr&type CPU, mac addresses
        int cpus;
        String cpuType;
        String macAddresses;
        //App Data - name, version, hash
        String appName;
        String version;

        Scanner sc = new Scanner(System.in);

        System.out.println("Processo de criação de pedido de licença");
        do {
            System.out.println("Enter your name:");
            userName = sc.nextLine().trim();
        } while (userName.isEmpty());

        do {
            System.out.println("Enter your email:");
            userEmail = sc.nextLine();
        } while (userEmail.isEmpty());

        do {
            System.out.println("Enter your nic:");
            userNIC = sc.nextLine();
        } while (userNIC.isEmpty());

        do {
            System.out.println("Enter the number of CPUs:");
            cpus = sc.nextInt();
            sc.nextLine();
        } while (cpus <= 0);

        do {
            System.out.println("Enter the type of CPUs:");
            cpuType = sc.nextLine();
        } while (cpuType.isEmpty());

        do {
            System.out.println("Enter the MAC Addresses:");
            macAddresses = sc.nextLine();
        } while (macAddresses.isEmpty());

        do {
            System.out.println("Enter the app's name:");
            appName = sc.nextLine();
        } while (appName.isEmpty());

        do {
            System.out.println("Enter the app's current version:");
            version = sc.nextLine();
        } while (version.isEmpty());

        sc.close();

        /*
        todo encriptar dados com cifra simétrica (AES, CBC, etc)
            encriptar chave e iv resultante dessa opeação com cifra assimétrica (chave publica do autor)
            colocar tudo numa pasta para ser enviado para o autor
        */

        //encrypt
        byte[] iv = generateIV();
        SecretKey key = generateKey();
        encrypt(appName, key, iv);

        //encrypt key and iv

        return true;
    }

    void showLicenseInfo() {

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
