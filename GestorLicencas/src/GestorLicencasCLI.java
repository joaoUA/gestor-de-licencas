import java.util.Scanner;

public class GestorLicencasCLI {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean exit = false;

        while(!exit) {
            System.out.println("Menu:");
            System.out.println("1 - Criar Licença");
            System.out.println("2 - Listar Licenças");
            System.out.println("0 - Sair");

            int op = scanner.nextInt();

            switch (op) {
                case 0:
                    //Sair
                    exit = true;
                case 1:
                    //Criar licença
                    break;
                case 2:
                    //Listar licenças
                    break;
            }
        }

        scanner.close();
    }
}
