package handshake;

import java.nio.ByteBuffer;

public class Greeting {
    private final static byte VER = 0x05;
    private final static byte NO_AUTH = 0x00;

     public static boolean isCorrect(byte[] message) {
        boolean result = false;
        int numberOfMethods = message[1];
        for (int i = 2; i < numberOfMethods + 2; i++) {
            if (message[i] == NO_AUTH)
                result = true;
        }

        return result && message[0] == VER;
    }

    public static ByteBuffer generateResponse() {
        ByteBuffer response = ByteBuffer.allocate(2);
        response.put(VER);
        response.put(NO_AUTH);
        return response;
    }
}

