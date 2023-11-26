import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class GestorLicencasCLI {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        Scanner scanner = new Scanner(System.in);
        boolean exit = false;

        LicenceManager lm = new LicenceManager();

        while(!exit) {
            System.out.println("Menu:");
            System.out.println("1 - Criar Licença");
            System.out.println("2 - Criar novo par de chaves");
            System.out.println("3 - Listar Licenças");
            System.out.println("0 - Sair");

            int op = scanner.nextInt();

            switch (op) {
                case 0:
                    //Sair
                    exit = true;
                case 1:
                    //Criar licença
                    lm.generateLicence();
                    break;
                case 2:
                    // Criar novo par de chaves
                    lm.generateKeyPair();
                case 3:
                    //Listar licenças
                    break;
            }
        }

        scanner.close();
    }
}
