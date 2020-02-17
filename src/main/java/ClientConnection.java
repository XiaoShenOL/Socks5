import java.nio.channels.SelectionKey;

class ClientConnection{
    private SelectionKey key;
    private int port;
    ClientConnection(SelectionKey key,int port){
        this.key=key;
        this.port=port;
    }

    public int getPort() {
        return port;
    }

    public SelectionKey getKey() {
        return key;
    }
}
