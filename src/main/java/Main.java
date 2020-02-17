import java.io.IOException;

public class Main {
    public static void main(String[] args) {
        if (args.length == 1){
            int port;
            try {
                port = Integer.parseInt(args[0]);
                try {
                    new Socks5Proxy(port).forward();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }catch (NumberFormatException ex){
                System.out.println("You gave incorrect parameter. Server needs a port number it will be bound to.");
                return;
            }
        }
    }
}