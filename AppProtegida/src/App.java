
public class App {
    public static void main(String[] args) {
        ControloExecucao ce = new ControloExecucao("AppProtegida", "1.0");

        if (!ce.isRegistered()) {
            System.out.println("Uso não autorizado da aplicação!");
            return;
        }

        System.out.println("Aplicação protegida em execução");
    }


}
