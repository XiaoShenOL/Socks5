import handshake.Connect;
import handshake.Greeting;
import org.xbill.DNS.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.channels.spi.SelectorProvider;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class Socks5Proxy {
    private static final String HOSTNAME = "localhost";
    private static final int BUFFER_SIZE = 8192;

    private int port;
    private Map<Integer, ClientConnection> dnslist = new HashMap<>();

    Socks5Proxy(int port) {
        this.port = port;
    }

    static class Attachment {
        ByteBuffer in;
        ByteBuffer out;
        SelectionKey peer;
    }

    private void initChannels(Selector selector, ServerSocketChannel serverChannel, DatagramChannel datagramChannel) throws IOException {
        serverChannel.configureBlocking(false);
        serverChannel.socket().bind(new InetSocketAddress(HOSTNAME, port));
        serverChannel.register(selector, serverChannel.validOps());

        datagramChannel.configureBlocking(false);
        datagramChannel.connect(new InetSocketAddress(ResolverConfig.getCurrentConfig().servers()[0], 53));
        datagramChannel.register(selector, SelectionKey.OP_READ);
    }

    private void selectorActions(SelectionKey key, DatagramChannel datagramChannel) throws IOException {
        try {
            if (key.isValid()) {
                if (key.isAcceptable()) {
                    accept(key);
                } else if (key.isConnectable()) {
                    connect(key);
                } else if (key.isReadable()) {
                    read(key, datagramChannel);
                } else if (key.isWritable()) {
                    write(key);
                }
            }
        }catch (Exception e){
            e.printStackTrace();
            close(key);
        }
    }

    private void accept(SelectionKey key) throws IOException {
        SocketChannel socketChannel = ((ServerSocketChannel) key.channel()).accept();
        socketChannel.configureBlocking(false);

        ByteBuffer byteBuffer = ByteBuffer.allocate(256);

        if (socketChannel.read(byteBuffer) < 0) {
            close(key);
            return;
        }
        if (Greeting.isCorrect(byteBuffer.array())) {
            socketChannel.write(ByteBuffer.wrap(Greeting.generateResponse().array(),0,2));
            socketChannel.register(key.selector(), SelectionKey.OP_READ);
        }
    }

    private void connect(SelectionKey key) throws IOException {
        SocketChannel channel = ((SocketChannel) key.channel());
        Attachment attachment = ((Attachment) key.attachment());
        channel.finishConnect();
        attachment.in = ByteBuffer.allocate(BUFFER_SIZE);
        attachment.in.put(ByteBuffer.wrap(Connect.generateResponse(port, true).array(),0,10)).flip();
        attachment.out = ((Attachment) attachment.peer.attachment()).in;
        ((Attachment) attachment.peer.attachment()).out = attachment.in;
        attachment.peer.interestOps(SelectionKey.OP_WRITE | SelectionKey.OP_READ);
        key.interestOps(0);
    }

    private void read(SelectionKey key, DatagramChannel dc) throws IOException {
        if (key.channel() instanceof SocketChannel) {
            int length;
            SocketChannel sc = (SocketChannel) key.channel();
            Attachment attachment = ((Attachment) key.attachment());
            if (attachment == null) {
                key.attach(attachment = new Attachment());
                attachment.in = ByteBuffer.allocate(BUFFER_SIZE);
            }
            if ((length=sc.read(attachment.in)) < 1) {
                close(key);
            } else if (attachment.peer == null) {
                readConnectRequest(key, attachment, dc,length);
            } else {
                attachment.peer.interestOps(attachment.peer.interestOps() | SelectionKey.OP_WRITE);
                key.interestOps(key.interestOps() ^ SelectionKey.OP_READ);
                attachment.in.flip();
            }
        } else {
            dnsResolve(key);
        }
    }

    private void write(SelectionKey key) throws IOException {
        SocketChannel channel = ((SocketChannel) key.channel());
        Attachment attachment = ((Attachment) key.attachment());
        if (channel.write(attachment.out) == -1) {
            close(key);
        } else if (attachment.out.remaining() == 0) {
            if (attachment.peer == null) {
                close(key);
            } else {
                attachment.out.clear();
                attachment.peer.interestOps(attachment.peer.interestOps() | SelectionKey.OP_READ);
                key.interestOps(key.interestOps() ^ SelectionKey.OP_WRITE);
            }
        }
    }

    private void checkSelector( DatagramChannel datagramChannel,Selector selector) {
        Iterator<SelectionKey> it = selector.selectedKeys().iterator();
        while (it.hasNext()) {
            try {
                SelectionKey key = it.next();
                it.remove();
                selectorActions(key, datagramChannel);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void readConnectRequest(SelectionKey key, Attachment attachment, DatagramChannel datagramChannel, int length) throws IOException {
        if (!Connect.isCorrect(attachment.in.array())) {
            throw new IOException("Error");
        } else {
            if (!Connect.isDNS(attachment.in.array())) {
                connectServer(Connect.getAddress(attachment.in.array()), attachment, key);
            } else {
                sendDnsToServ(datagramChannel, attachment, key,length);
            }
        }
    }



    private void connectServer(SocketAddress address, Attachment attachment, SelectionKey key) throws IOException {
        SocketChannel peer = SocketChannel.open();
        peer.configureBlocking(false);
        peer.connect(address);
        if(peer.isConnectionPending()){
            SelectionKey peerKey = peer.register(key.selector(), SelectionKey.OP_CONNECT);
            key.interestOps(0);
            attachment.peer = peerKey;
            Attachment peerAttachment = new Attachment();
            peerAttachment.peer = key;
            peerKey.attach(peerAttachment);
            attachment.in.clear();
        }else
            ((SocketChannel)key.channel()).write(ByteBuffer.wrap(Connect.generateResponse(port, false).array(),0,10));
    }

    public void forward() throws IOException {
        Selector selector = SelectorProvider.provider().openSelector();
        try (ServerSocketChannel ssChannel = ServerSocketChannel.open();
             DatagramChannel dataChannel = DatagramChannel.open()) {
            initChannels(selector,ssChannel, dataChannel);
            while ( selector.select()>-1) {
                checkSelector( dataChannel,selector);
            }
        }
    }

    private void close(SelectionKey key) throws IOException {
        key.cancel();
        key.channel().close();
        SelectionKey peerKey = ((Attachment) key.attachment()).peer;
        if (peerKey != null) {
            ((Attachment) peerKey.attachment()).peer = null;
            if ((peerKey.interestOps() & SelectionKey.OP_WRITE) == 0) {
                ((Attachment) peerKey.attachment()).out.flip();
            }
            peerKey.interestOps(SelectionKey.OP_WRITE);
        }
    }

    private void sendDnsToServ(DatagramChannel datagramChannel, Attachment attachment, SelectionKey key,int len) throws IOException {
        Name name = org.xbill.DNS.Name.fromString(Connect.getDomain(attachment.in.array()), Name.root);
        Record rec = Record.newRecord(name, Type.A, DClass.IN);
        Message dns_message = Message.newQuery(rec);
        datagramChannel.write(ByteBuffer.wrap(dns_message.toWire()));
        dnslist.put(dns_message.getHeader().getID(), new ClientConnection(key, Connect.getPort(attachment.in.array())));
    }

    private void dnsResolve(SelectionKey key) throws IOException {
        DatagramChannel datagramChannel = (DatagramChannel) key.channel();
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        if (datagramChannel.read(buffer) <= 0) return;
        Message msg = new Message(buffer.array());
        Record[] recs = msg.getSectionArray(1);
        for (Record rec : recs) {
            if (rec instanceof ARecord) {
                ARecord arec = (ARecord) rec;
                int id = msg.getHeader().getID();
                SelectionKey cliKey = dnslist.get(id).getKey();
                connectServer(new InetSocketAddress(arec.getAddress(), dnslist.get(id).getPort()), (Attachment) cliKey.attachment(), cliKey);
                dnslist.remove(id);
                break;
            }
        }
    }
}
