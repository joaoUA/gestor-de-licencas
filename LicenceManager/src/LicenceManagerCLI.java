import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

public class LicenceManagerCLI {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException, InvalidKeySpecException {
        Scanner scanner = new Scanner(System.in);
        boolean exit = false;

        LicenceManager lm = new LicenceManager();

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
                    //Verifica se existe ficheiros com chaves
                    Path filePath = Paths.get(System.getProperty("user.home"), "licence_request");
                    if (!Files.exists(filePath)) {
                        System.out.println("Não foi encontrado o ficheiro!");
                        break;
                    }
                    //
                    lm.generateLicence();
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
