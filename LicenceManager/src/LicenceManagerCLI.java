import org.bouncycastle.operator.OperatorCreationException;
import org.json.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class LicenceManagerCLI {

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException, InvalidKeySpecException, UnrecoverableEntryException, CertificateException, KeyStoreException, OperatorCreationException {
        Scanner scanner = new Scanner(System.in);
        boolean exit = false;

        //todo resolve, remove dependency injection
        LicenceManager lm = new LicenceManager(scanner);

        while (!exit) {
            System.out.println("Menu:");
            System.out.println("1. Criar licença");
            System.out.println("2. Criar par de chaves");
            System.out.println("3. Listar licenças");
            System.out.println("0. Sair");

            int op = scanner.nextInt();
            scanner.nextLine();

            switch (op) {
                case 0: //sair
                    exit = true;
                    break;
                case 1: //criar licença
                    System.out.println("Path for the directory with the licence request files:");
                    Path licenceRequestPath = Paths.get(scanner.nextLine().trim());

                    if (!Files.isDirectory(licenceRequestPath)) {
                        System.out.println("Directory not found!");
                        break;
                    }

                    LicenceManager.DecryptResult decryptResult = lm.decryptLicenceRequest(licenceRequestPath);

                    JSONObject jsonObject = new JSONObject(decryptResult.licenceInfo());
                    lm.showLicenceRequestInfo(jsonObject);

                    boolean generate = false;
                    boolean generateInputValid = false;

                    do {
                        System.out.println("Generate licence: [Y/N]");
                        String generateInput = scanner.nextLine().trim().toUpperCase();
                        if (generateInput.equals("Y")) {
                            generate = true;
                            generateInputValid = true;
                        } else if (generateInput.equals("N")) {
                            generate = false;
                            generateInputValid = true;
                        }
                    } while (!generateInputValid);

                    if (generate) {
                        lm.generateLicence(decryptResult.licenceInfo(), decryptResult.publicKey());
                    }

                    break;
                case 2: //criar par de chaves
                    lm.generateKeyPair();
                    break;
                case 3: //listar licenças
                    break;
            }
        }

        scanner.close();
    }
}
