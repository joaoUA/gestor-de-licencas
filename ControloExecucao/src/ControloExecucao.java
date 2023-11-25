import java.util.Scanner;

public class ControloExecucao {

    public ControloExecucao(String appName, String version) {

    }

    boolean isRegistered() {
        return false;
    }

    boolean startRegistration() {
        //User Data - name, email, nic, cc certificate
        String userName;
        String userEmail;
        String userNIC;
        //System Data - nr&type CPU, mac addresses
        int cpus;
        String cpuType;
        String macAddresses;
        //App Data - name, version, hash
        String appName;
        String version;

        Scanner sc = new Scanner(System.in);

        System.out.println("Processo de criação de pedido de licença");
        do {
            System.out.println("Enter your name:");
            userName = sc.nextLine().trim();
        } while (userName.isEmpty());

        do {
            System.out.println("Enter your email:");
            userEmail = sc.nextLine();
        } while (userEmail.isEmpty());

        do {
            System.out.println("Enter your nic:");
            userNIC = sc.nextLine();
        } while (userNIC.isEmpty());

        do {
            System.out.println("Enter the number of CPUs:");
            cpus = sc.nextInt();
            sc.nextLine();
        } while (cpus <= 0);

        do {
            System.out.println("Enter the type of CPUs:");
            cpuType = sc.nextLine();
        } while (cpuType.isEmpty());

        do {
            System.out.println("Enter the MAC Addresses:");
            macAddresses = sc.nextLine();
        } while (macAddresses.isEmpty());

        do {
            System.out.println("Enter the app's name:");
            appName = sc.nextLine();
        } while (appName.isEmpty());

        do {
            System.out.println("Enter the app's current version:");
            version = sc.nextLine();
        } while (version.isEmpty());

        sc.close();

        return true;
    }

    void showLicenseInfo() {

    }

}
