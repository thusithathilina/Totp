package org.ttd.totp;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

public class Totp {
    public static String hotp(String key, long counter, int digits, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] decodedKey = new Base32().decode(key);
        byte[] counterBytes = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(counter).array();

        SecretKeySpec keySpec = new SecretKeySpec(decodedKey, algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(keySpec);

        byte[] macBytes = mac.doFinal(counterBytes);
        int offset = macBytes[macBytes.length - 1] & 0x0F;
        int binary = ByteBuffer.wrap(macBytes, offset, 4).getInt() & 0x7FFFFFFF;

        return String.format("%0" + digits + "d", binary % (int)(Math.pow(10, digits)));
    }

    public static String totp(String key, long timeStep, int digits, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        long counter = Instant.now().getEpochSecond() / timeStep;
        return hotp(key, counter, digits, algorithm);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        String key = "JBSWY3DPEHPK3PXP";
        int timeStep = 30;
        int digits = 6;
        String algorithm = "HmacSHA1";

        System.out.println(totp(key, timeStep, digits, algorithm));
    }
}
