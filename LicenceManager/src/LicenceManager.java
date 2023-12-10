import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.json.JSONObject;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;
import java.util.UUID;

public class LicenceManager {
    private static final String keyStoreType = "JKS";
    private static final String keyStoreFileName = "myKeyStore.jks";
    private final KeyStore keyStore;
    private static final String keyPairAlias = "rsa-encryption-key-pair";
    private final String keyStorePass;

    private static final String licencesFolderName = "licences";
    private static final String licenceFolderNameDistApp = "Licence_Manager";
    private static final String licenceDataFileName = "licence_info";
    private static final String licenceKeyFileName = "licence_key";
    private static final String licenceIVFileName = "licence_iv";

    private static final String licenceRequestKeyFileName = "licence_request_key";
    private static final String licenceRequestIVFileName = "licence_request_iv";
    private static final String licenceRequestDataFileName = "licence_request_data";
    private static final String licenceRequestPublicKey = "licence_request_public_key";

    public record DecryptResult(String licenceInfo, PublicKey publicKey){}

    private KeyPair keyPair;

    public LicenceManager(Scanner scanner) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, KeyStoreException, CertificateException, UnrecoverableEntryException, OperatorCreationException {
        Path keyStorePath = Path.of(keyStoreFileName);

        if (Files.exists(keyStorePath)) {
            System.out.println("KeyStore file found: " + keyStorePath);
            keyStore = KeyStore.getInstance(keyStoreType);

            String keyStorePassInput;
            do {
                System.out.println("KeyStore Password: ");
                keyStorePassInput = scanner.nextLine().trim();
            } while (keyStorePassInput.isEmpty());
            keyStorePass = keyStorePassInput;
            keyStore.load(new FileInputStream(keyStoreFileName), keyStorePass.toCharArray());
            System.out.println("KeyStore loaded successfully!");
        } else {
            System.out.println("KeyStore file NOT found: " + keyStorePath);
            keyStore = KeyStore.getInstance(keyStoreType);

            String keyStorePassInput;
            do {
                System.out.println("Define your KeyStore password:");
                keyStorePassInput = scanner.nextLine().trim();
            } while (keyStorePassInput.isEmpty());
            keyStorePass = keyStorePassInput;
            keyStore.load(null, keyStorePass.toCharArray());
            FileOutputStream fos = new FileOutputStream(keyStoreFileName);
            keyStore.store(fos, keyStorePass.toCharArray());
            fos.close();
            System.out.println("New KeyStore created.");
        }

        if (keyStore.containsAlias(keyPairAlias)) {
            System.out.println("KeyPair found with alias: " + keyPairAlias);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyPairAlias, new KeyStore.PasswordProtection(keyStorePass.toCharArray()));
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();

            keyPair = new KeyPair(publicKey, privateKey);
            System.out.println("KeyPair loaded successfully!");
        } else {
            System.out.println("KeyPair not found with alias: " + keyPairAlias);

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();

            String subjectName = "CN=Self-Signed";
            Certificate certificate = generateCertificate(keyPair, subjectName);
            keyStore.setKeyEntry(keyPairAlias, keyPair.getPrivate(), keyStorePass.toCharArray(), new Certificate[]{certificate});

            FileOutputStream fos = new FileOutputStream(keyStoreFileName);
            keyStore.store(fos, keyStorePass.toCharArray());
            fos.close();

            savePublicKeyToFile();

            System.out.println("New KeyPair created, no previous KeyPair found for alias: " + keyPairAlias);
        }
    }

    private void savePublicKeyToFile() throws IOException {
        Path myPublicKey = Paths.get(System.getProperty("user.home"), "myPublicKey", "pk");

        FileOutputStream fos = new FileOutputStream(myPublicKey.toFile());
        fos.write(keyPair.getPublic().getEncoded());
        fos.close();
    }

    public byte[] getPublicKey() {
        return keyPair.getPublic().getEncoded();
    }
    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public DecryptResult decryptLicenceRequest(Path licenceRequestFolder) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        Path licenceRequestKeyPath = licenceRequestFolder.resolve(licenceRequestKeyFileName);
        Path licenceRequestIVPath = licenceRequestFolder.resolve(licenceRequestIVFileName);
        Path licenceRequestDataPath = licenceRequestFolder.resolve(licenceRequestDataFileName);
        Path licenceRequestPublickKey = licenceRequestFolder.resolve(licenceRequestPublicKey);

        if (!Files.exists(licenceRequestKeyPath)
            || !Files.exists(licenceRequestIVPath)
            || !Files.exists(licenceRequestDataPath)
            || !Files.exists(licenceRequestPublickKey)) {
            System.out.println("Missing files in provided directory!");
            return null;
        }

        Cipher rsaDecipher = Cipher.getInstance("RSA");
        rsaDecipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        byte[] licenceReqKeyBytes = Files.readAllBytes(licenceRequestKeyPath);
        byte[] licenceReqIVBytes = Files.readAllBytes(licenceRequestIVPath);

        byte[] decryptedKeyBytes = rsaDecipher.doFinal(licenceReqKeyBytes);
        byte[] decryptedIVBytes = rsaDecipher.doFinal(licenceReqIVBytes);

        SecretKeySpec licenceKey = new SecretKeySpec(decryptedKeyBytes, "AES");
        IvParameterSpec licenceIV = new IvParameterSpec(decryptedIVBytes);

        Cipher aesDecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesDecipher.init(Cipher.DECRYPT_MODE, licenceKey, licenceIV);

        byte[] licenceReqDataBytes = Files.readAllBytes(licenceRequestDataPath);
        byte[] decryptedLDataBytes = aesDecipher.doFinal(licenceReqDataBytes);

        String licenceInfo = new String(decryptedLDataBytes);

        byte[] licenceReqPKBytes = Files.readAllBytes(licenceRequestPublickKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey appPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(licenceReqPKBytes));

        return new DecryptResult(licenceInfo, appPublicKey);
    }
    public void generateLicence(String licenceInfo, PublicKey appPublicKey) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        //Encrypt Licence Info
        SecretKey key = generateKey();
        byte[] iv = generateIV();
        byte[] encryptedData = encrypt(licenceInfo, key, iv);

        String uniqueLicenceFolderName = generateLicenceFolderName();

        //Save Licence Destined to distributed app:
        Path appLicenceFile = Paths.get(System.getProperty("user.home"), licenceFolderNameDistApp , uniqueLicenceFolderName, licenceDataFileName);
        Files.createDirectories(appLicenceFile.getParent());
        saveToFile(encryptedData, appLicenceFile);

        //Save Licence 'Copy' for LicenceManager
        Path lmLicenceFilePath = Paths.get(System.getProperty("user.dir"), licencesFolderName, uniqueLicenceFolderName, licenceDataFileName);
        Files.createDirectories(lmLicenceFilePath.getParent());
        saveToFile(encryptedData, lmLicenceFilePath);

        //Encrypt & Save Encrypted Key & IV to distributed app:
        Cipher appRSACipher = Cipher.getInstance("RSA");
        appRSACipher.init(Cipher.ENCRYPT_MODE, appPublicKey);
        byte[] appEncryptedKey = appRSACipher.doFinal(key.getEncoded());
        byte[] appEncryptedIV = appRSACipher.doFinal(iv);

        Path appLicenceKeyFile = Paths.get(System.getProperty("user.home"), licenceFolderNameDistApp, uniqueLicenceFolderName, licenceKeyFileName);
        saveToFile(appEncryptedKey, appLicenceKeyFile);
        Path appLicenceIVFile = Paths.get(System.getProperty("user.home"), licenceFolderNameDistApp, uniqueLicenceFolderName, licenceIVFileName);
        saveToFile(appEncryptedIV, appLicenceIVFile);

        //Encrypt Save Encrypted Key & IV for LicenceManager:
        Cipher lmRSACipher = Cipher.getInstance("RSA");
        lmRSACipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] lmEncryptedKey = lmRSACipher.doFinal(key.getEncoded());
        byte[] lmEncryptedIV = lmRSACipher.doFinal(iv);

        Path lmLicenceKeyFile = Paths.get(System.getProperty("user.dir"), licencesFolderName, uniqueLicenceFolderName, licenceKeyFileName);
        saveToFile(lmEncryptedKey, lmLicenceKeyFile);
        Path lmLicenceIVFile = Paths.get(System.getProperty("user.dir"), licencesFolderName, uniqueLicenceFolderName, licenceIVFileName);
        saveToFile(lmEncryptedIV, lmLicenceIVFile);
    }
    public void generateKeyPair() throws NoSuchAlgorithmException, IOException, CertificateException, OperatorCreationException, KeyStoreException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();

        String subjectName = "CN=Self-Signed";
        Certificate certificate = generateCertificate(keyPair, subjectName);
        keyStore.setKeyEntry(keyPairAlias, keyPair.getPrivate(), keyStorePass.toCharArray(), new Certificate[]{certificate});

        FileOutputStream fos = new FileOutputStream(keyStoreFileName);
        keyStore.store(fos, keyStorePass.toCharArray());
        fos.close();

    }
    public void showLicenceReqInfo(JSONObject jsonObject) {
        System.out.println("===================");
        System.out.println("LICENCE REQUEST");

        System.out.println();

        System.out.println("User information:");
        System.out.println("Name - " + jsonObject.get("userName"));
        System.out.println("NIC - " + jsonObject.get("userNIC"));
        System.out.println("Email - " + jsonObject.get("userEmail"));

        System.out.println();

        System.out.println("System information:");
        System.out.println("CPU Arch - " + jsonObject.get("cpuArchitecture"));
        System.out.println("CPU Id - " + jsonObject.get("cpuIdentifier"));
        System.out.println("CPU Number - " + jsonObject.get("cpuNumber"));
        System.out.println("MAC Addr - " + jsonObject.get("macAddress"));

        System.out.println();

        System.out.println("App information: ");
        System.out.println("Name - " + jsonObject.get("appName"));
        System.out.println("Version - " + jsonObject.get("appVersion"));

        System.out.println();

        System.out.println("===================");
    }

    public void showLicenceInfo(JSONObject jsonObject) {
        System.out.println("Name - " + jsonObject.get("userName"));
        System.out.println("NIC - " + jsonObject.get("userNIC"));
        System.out.println("Email - " + jsonObject.get("userEmail"));
        System.out.println("CPU Arch - " + jsonObject.get("cpuArchitecture"));
        System.out.println("CPU Id - " + jsonObject.get("cpuIdentifier"));
        System.out.println("CPU Number - " + jsonObject.get("cpuNumber"));
        System.out.println("MAC Addr - " + jsonObject.get("macAddress"));
        System.out.println("Name - " + jsonObject.get("appName"));
        System.out.println("Version - " + jsonObject.get("appVersion"));
    }

    public String decryptLicence(Path licenceFolder) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Path licenceFile = licenceFolder.resolve("licence_info");
        Path keyFile = licenceFolder.resolve("licence_key");
        Path ivFile = licenceFolder.resolve("licence_iv");

        if (!Files.exists(licenceFile) || !Files.exists(keyFile) || !Files.exists(ivFile)) {
            System.out.println("Missing files for licence on: " + licenceFolder);
            return null;
        }

        Cipher rsaDecipher = Cipher.getInstance("RSA");
        rsaDecipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        byte[] licenceKeyBytes = rsaDecipher.doFinal(Files.readAllBytes(keyFile));
        byte[] licenceIVBytes = rsaDecipher.doFinal(Files.readAllBytes(ivFile));

        SecretKeySpec key = new SecretKeySpec(licenceKeyBytes, "AES");
        IvParameterSpec iv = new IvParameterSpec(licenceIVBytes);

        Cipher aesDecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesDecipher.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] licenceInfo = aesDecipher.doFinal(Files.readAllBytes(licenceFile));

        return new String(licenceInfo);
    }

    public Path getLicencesDirectory() {
        return Paths.get(System.getProperty("user.dir"), licencesFolderName);
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
        FileOutputStream fos = new FileOutputStream(path.toFile(), false);
        fos.write(data);
        fos.close();
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

    private String generateLicenceFolderName() {
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmssSSS");
        String timestamp = now.format(formatter);

        String random = UUID.randomUUID().toString().replaceAll("-", "");

        return timestamp + "_" + random;
    }
}
