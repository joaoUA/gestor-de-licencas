
public class App {
    public static void main(String[] args) {
        ControloExecucao ce = new ControloExecucao("AppProtegida", "1.0");

        if (!ce.isRegistered()) {
            System.out.println("Uso não autorizado da aplicação!");

            if (ce.startRegistration()) {
                System.out.println("Processo de criação de pedido de licença executado com sucesso!");
            } else {
                System.out.println("Erro ao tentar criar pedido de licença!");
            }
            return;
        }

        System.out.println("Aplicação protegida em execução");
    }


}
