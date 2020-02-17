package handshake;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class Connect {
    private final static byte VER = 0x05;
    private final static byte COMMAND = 0x01;
    private final static byte RESERVED = 0x00;
    private final static byte IPv4 = 0x01;
    private final static byte DOMAIN = 0x03;

    private final static int NUMBER_OF_DOMAIN_POSITION = 5;

    private final static byte REQUEST_GRANTED = 0x00;
    private final static byte GENERAL_FAILURE = 0x01;

    public static boolean isCorrect(byte[] message) {
        return message[0] == VER && message[1] == COMMAND && message[2] == RESERVED && (message[3] == IPv4 || message[3] == DOMAIN);
    }

    public static InetAddress getIPv4 (byte[] message) throws UnknownHostException {
        return InetAddress.getByAddress(new byte[]{
                message[4],
                message[5],
                message[6],
                message[7]
        });
    }

    public static int getPort(byte[] message) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(2);
        byte[] portBytes = Arrays.copyOfRange(message, message.length - 2, message.length);
        byteBuffer.put(portBytes);
        return byteBuffer.getShort();
    }

    public static boolean isDNS(byte[] message) {
        return message[3] == IPv4;
    }

    public static String getDomain(byte[] message) {
        int domainLength = message[4];
        byte[] domain_bytes = Arrays.copyOfRange(message, NUMBER_OF_DOMAIN_POSITION, domainLength + NUMBER_OF_DOMAIN_POSITION);
        return new String(domain_bytes);
    }

    public static InetSocketAddress getAddress(byte[] message) throws UnknownHostException {
        return new InetSocketAddress(getIPv4(message), getPort(message));
    }

    public static ByteBuffer generateResponse(int port, boolean isConnected) {
        ByteBuffer response = ByteBuffer.allocate(10);
        byte[] arr;
        if (isConnected)
            arr = new byte[]{
                    VER,
                    REQUEST_GRANTED,
                    RESERVED,
                    IPv4,
                    0x7F,
                    0x00,
                    0x00,
                    0x01,
                    (byte) ((port >> 8) & 0xFF),
                    (byte) (port & 0xFF)};
        else
            arr = new byte[]{
                    VER,
                    GENERAL_FAILURE,
                    RESERVED,
                    IPv4,
                    0x7F,
                    0x00,
                    0x00,
                    0x01,
                    (byte) ((port >> 8) & 0xFF),
                    (byte) (port & 0xFF)};
        response.put(arr);
        return response;
    }
}
