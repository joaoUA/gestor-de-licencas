import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Date;

public class LicenceManager {
    private static final String keyStoreType = "JKS";
    private static final String keyStoreFileName = "myKeyStore.jks";
    private final KeyStore keyStore;
    private static final String keyPairAlias = "rsa-encryption-key-pair";
    private char[] keyStorePass = "password".toCharArray();

    private KeyPair keyPair;

    public LicenceManager() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, KeyStoreException, CertificateException, UnrecoverableEntryException, OperatorCreationException {
        Path keyStorePath = Path.of(keyStoreFileName);
        if (Files.exists(keyStorePath)) {
            System.out.println("KeyStore file found: " + keyStorePath);
            keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(new FileInputStream(keyStoreFileName), keyStorePass);
            System.out.println("KeyStore loaded successfully!");
        } else {
            System.out.println("KeyStore file NOT found: " + keyStorePath);
            keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null, keyStorePass);
            FileOutputStream fos = new FileOutputStream(keyStoreFileName);
            keyStore.store(fos, keyStorePass);
            fos.close();
            System.out.println("New KeyStore created.");
        }

        if (keyStore.containsAlias(keyPairAlias)) {
            System.out.println("KeyPair found with alias: " + keyPairAlias);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyPairAlias, new KeyStore.PasswordProtection(keyStorePass));
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
            keyStore.setKeyEntry(keyPairAlias, keyPair.getPrivate(), keyStorePass, new Certificate[]{certificate});

            FileOutputStream fos = new FileOutputStream(keyStoreFileName);
            keyStore.store(fos, keyStorePass);
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
    public void generateKeyPair() throws NoSuchAlgorithmException, IOException, CertificateException, OperatorCreationException, KeyStoreException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();

        String subjectName = "CN=Self-Signed";
        Certificate certificate = generateCertificate(keyPair, subjectName);
        keyStore.setKeyEntry(keyPairAlias, keyPair.getPrivate(), keyStorePass, new Certificate[]{certificate});

        FileOutputStream fos = new FileOutputStream(keyStoreFileName);
        keyStore.store(fos, keyStorePass);
        fos.close();

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
