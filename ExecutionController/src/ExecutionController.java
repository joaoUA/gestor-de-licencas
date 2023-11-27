import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
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

            System.out.printf("Par de chaves guarda com sucesso em:\n%s\n%s%n", publicKeyPath, privateKeyPath);

        } else {
            System.out.println("Encontrado com sucesso par de chaves.");
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyPath);
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);

            //load pair of keys
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            System.out.println("Par de chaves, carregadas do ficheiro com sucesso.");
        }

    }

    public boolean isRegistered() {
        return false;
    }
    public boolean startRegistration() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
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

        /*
        todo encriptar dados com cifra simétrica (AES/CBC)
            encriptar chave & iv resultante, com cifra assimétrica (RSA, e chave pública do autor)
            colocar tudo numa pasta para ser enviado para o autor
        */

        byte[] iv = generateIV();
        SecretKey key = generateKey();

        byte[][] encryptedData = new byte[8][];
        encryptedData[0] = encrypt(username, key, iv);
        encryptedData[1] = encrypt(email, key, iv);
        encryptedData[2] = encrypt(nic, key, iv);
        encryptedData[3] = encrypt(String.valueOf(cpus), key, iv);
        encryptedData[4] = encrypt(cpuType, key, iv);
        encryptedData[5] = encrypt(macAddresses, key, iv);
        encryptedData[6] = encrypt(appName, key, iv);
        encryptedData[7] = encrypt(version, key, iv);

        Path filePath = Paths.get( System.getProperty("user.home"), "licence_request", "licence_request_data");
        System.out.println(filePath);
        Files.createDirectories(filePath.getParent());

        BufferedOutputStream os = new BufferedOutputStream(new FileOutputStream(filePath.toFile()));
        for (byte[] data : encryptedData) {
            os.write(data);
            os.write('\n');
        }
        os.close();
        System.out.println("Dados necessários para pedido de licença, guardados com sucesso!");

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
