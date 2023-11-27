import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class App {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException {
        ExecutionController ec = new ExecutionController("app", "1.0");

        if (!ec.isRegistered()) {
            System.out.println("Uso não autorizado da aplicação!");
            System.out.println("A iniciar processo de pedido de licença.");
            if (ec.startRegistration()) {
                System.out.println("Processo de criação de pedido de licença concluído com sucesso!");
            } else {
                System.out.println("Processo de criação de pedido de licença concluído sem sucesso!");
            }
            return;
        }

        System.out.println("Aplicação protegida em execução");
    }
}
