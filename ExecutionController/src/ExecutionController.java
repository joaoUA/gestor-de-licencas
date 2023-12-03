import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;

public class ExecutionController {
    private static final String keyStoreFileName = "myKeyStore.jks";
    private static final String keyStoreType = "JKS";
    private static final String keyPairAlias = "rsa-encryption-key-pair";
    private KeyStore keyStore;
    private String keyStorePassword;
    private KeyPair keyPair;

    private final String appName;
    private final String version;

    public ExecutionController(String appName, String version) {
        this.appName = appName;
        this.version = version;
    }

    public boolean isRegistered() throws KeyStoreException, CertificateException, IOException,
            NoSuchAlgorithmException, UnrecoverableEntryException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
            OperatorCreationException {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Checking if KeyStore exists");
        Path keyStorePath = Paths.get(System.getProperty("user.dir"), keyStoreFileName);

        if (!Files.exists(keyStorePath)) {
            System.out.println("KeyStore file not found: " + keyStorePath);
            System.out.println("Creating new KeyStore...");
            keyStore = KeyStore.getInstance(keyStoreType);

            do {
                System.out.println("Define the password for the new KeyStore:");
                keyStorePassword = scanner.nextLine().trim();
            } while (keyStorePassword.isEmpty());

            keyStore.load(null, keyStorePassword.toCharArray());
            FileOutputStream fos = new FileOutputStream(keyStorePath.toFile());
            keyStore.store(fos, keyStorePassword.toCharArray());
            fos.close();

            System.out.println("New KeyStore successfully created!");
            return false;
        }

        System.out.println("KeyStore file found: " + keyStorePath);
        keyStore = KeyStore.getInstance(keyStoreType);

        do {
            System.out.println("Introduce the KeyStore's password: ");
            keyStorePassword = scanner.nextLine().trim();
        } while (keyStorePassword.isEmpty());

        //todo handle in case the password is incorrect, instead of throwing
        keyStore.load(new FileInputStream(keyStorePath.toFile()), keyStorePassword.toCharArray());

        System.out.println("KeyStore successfully loaded!");

        //todo add custom KeyPairAlias depending on user/system/app
        if (!keyStore.containsAlias(keyPairAlias)) {
            System.out.println("Couldn't find KeyPair in KeyStore: " + keyPairAlias);
            System.out.println("Creating new KeyPair...");

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();

            Certificate certificate = generateCertificate(keyPair, "CN=Self-Signed");
            keyStore.setKeyEntry(keyPairAlias,
                    keyPair.getPrivate(),
                    keyStorePassword.toCharArray(),
                    new Certificate[]{certificate});

            FileOutputStream fos = new FileOutputStream(keyStorePath.toFile());
            keyStore.store(fos, keyStorePassword.toCharArray());
            fos.close();
            System.out.println("New KeyPair created and stored in the KeyStore, alias: " + keyPairAlias);

            return false;
        }

        System.out.println("KeyPair found in KeyStore with alias: " + keyPairAlias);

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyPairAlias,
                new KeyStore.PasswordProtection(keyStorePassword.toCharArray()));

        PrivateKey privateKey = privateKeyEntry.getPrivateKey();
        PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();

        keyPair = new KeyPair(publicKey, privateKey);

        System.out.println("Successfully loaded KeyPair with alias: " + keyPairAlias);

        String licenceFolderPathInput;
        do {
            System.out.println("Introduce the path for your licence folder:");
            licenceFolderPathInput = scanner.nextLine().trim();
        } while (licenceFolderPathInput.isEmpty());

        Path licenceFolderPath = Path.of(licenceFolderPathInput);
        Path licencePath = Paths.get(String.valueOf(licenceFolderPath), "licence");
        Path licenceKeyPath = Paths.get(String.valueOf(licenceFolderPath), "licence_key");
        Path licenceIVPath = Paths.get(String.valueOf(licenceFolderPath), "licence_iv");

        if (!Files.exists(licencePath) || !Files.exists(licenceKeyPath) || !Files.exists(licenceIVPath)) {
            System.out.println("There are missing files on the licence folder");
            return false;
        }

        byte[] encryptedLicenceKey = Files.readAllBytes(licenceKeyPath);
        byte[] encryptedLicenceIV = Files.readAllBytes(licenceIVPath);

        Cipher rsaDecipher = Cipher.getInstance("RSA");
        rsaDecipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedLicenceKey = rsaDecipher.doFinal(encryptedLicenceKey);
        byte[] decryptedLicenceIV = rsaDecipher.doFinal(encryptedLicenceIV);

        Cipher aesDecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec licenceKeySpec = new SecretKeySpec(decryptedLicenceKey, "AES");
        aesDecipher.init(Cipher.DECRYPT_MODE, licenceKeySpec, new IvParameterSpec(decryptedLicenceIV));
        byte[] encryptedLicence = Files.readAllBytes(licencePath);
        byte[] decryptedLicence = aesDecipher.doFinal(encryptedLicence);

        System.out.printf("Licence info:\n %s", new String(decryptedLicence, StandardCharsets.UTF_8));
        return true;
    }
    
    public boolean startRegistration() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String userName;
        String userEmail;
        String userNIC;
        int cpus;
        String cpusType;
        String macAddresses;
        String appName;
        String appVersion;

        System.out.println("Starting registration process!");
        userName = "joao";
        userEmail = "joao@gmail.com";
        userNIC = "999888777";
        cpus = 2;
        cpusType = "intel";
        macAddresses = "127.0.0.1";
        appName = this.appName;
        appVersion = this.version;

        //Check for author's public key
        Path authorKeyPath = Paths.get(System.getProperty("user.dir"), "author_keys", "author_public_key");
        if (!Files.exists(authorKeyPath)) {
            System.out.println("Author's public key not found at expected location");
            return false;
        }

        byte[] authorKeyBytes = Files.readAllBytes(authorKeyPath);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey authorKey = keyFactory.generatePublic(new X509EncodedKeySpec(authorKeyBytes));

        byte[] iv = generateIV();
        SecretKey key = generateKey();

        String formattedData = "%s\n%s\n%s\n%d\n%s\n%s\n%s\n%s".formatted(
                userName,
                userEmail,
                userNIC,
                cpus,
                cpusType,
                macAddresses,
                appName,
                appVersion);
        byte[] encryptedData = encrypt(formattedData, key, iv);

        //todo allow user to input destination path of licence request folder


        String licenceRequestFolderName = "licence_request";
        String licenceRequestFileName = "licence_request_data";
        Path encryptedFilePath = Paths.get(System.getProperty("user.home"), licenceRequestFolderName, licenceRequestFileName);
        Files.createDirectories(encryptedFilePath.getParent());
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(encryptedFilePath.toFile()));
        bos.write(encryptedData);
        bos.close();
        System.out.println("Successfully stored encrypted data!");

        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, authorKey);

        byte[] encryptedKey = rsaCipher.doFinal(key.getEncoded());
        byte[] encryptedIV = rsaCipher.doFinal(iv);

        String licenceRequestKeyFileName = "licence_request_key";
        Path encryptedKeyPath = Paths.get(System.getProperty("user.home"), licenceRequestFolderName, licenceRequestKeyFileName);
        bos = new BufferedOutputStream(new FileOutputStream(encryptedKeyPath.toFile()));
        bos.write(encryptedKey);
        bos.close();
        System.out.println("Successfully stored encrypted key!");

        String licenceRequestIVFileName = "licence_request_iv";
        Path encryptedIVPath = Paths.get(System.getProperty("user.home"), licenceRequestFolderName, licenceRequestIVFileName);
        bos = new BufferedOutputStream(new FileOutputStream(encryptedIVPath.toFile()));
        bos.write(encryptedIV);
        bos.close();
        System.out.println("Successfully stored encrypted iv!");

        String publicKeyFileName = "licence_request_public_key";
        Path appPublicKeyPath = Paths.get(System.getProperty("user.home"), licenceRequestFolderName, publicKeyFileName);
        bos = new BufferedOutputStream(new FileOutputStream(appPublicKeyPath.toFile()));
        bos.write(keyPair.getPublic().getEncoded());
        bos.close();
        System.out.println("Successfully stored this instance's public key!");

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

    private Certificate generateCertificate(KeyPair keyPair, String subjectName) throws CertificateException, OperatorCreationException {
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name(subjectName);
        BigInteger certSerialNumber = new BigInteger(Long.toString(now));

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1);

        Date endDate = calendar.getTime();

        String signatureAlgorithm = "SHA256WithRSA";

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                dnName,
                certSerialNumber,
                startDate,
                endDate,
                dnName,
                keyPair.getPublic());

        return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certificateBuilder.build(contentSigner));
    }
}
