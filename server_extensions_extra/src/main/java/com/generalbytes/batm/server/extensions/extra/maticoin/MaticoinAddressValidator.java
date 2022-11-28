package com.generalbytes.batm.server.extensions.extra.maticoin;

import com.generalbytes.batm.server.extensions.ICryptoAddressValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.web3j.crypto.Hash;

public class MaticoinAddressValidator implements ICryptoAddressValidator {

    private static final Logger log = LoggerFactory.getLogger(MaticoinAddressValidator.class);

    private static final String HEX_CHARS = "0123456789abcdef";

    public static String encodeAddressToChecksumedAddress(byte[] addrBytes) {
        String address = bytesToHexString(addrBytes);
        return encodeAddressToChecksumedAddress(address);
    }

    public static String encodeAddressToChecksumedAddress(String address) {
        if (address == null) {
            return null;
        }
        address = address.trim();
        if (address.isEmpty()) {
            return null;
        }

        final String addressHash = bytesToHexString(Hash.sha3(address.toLowerCase().getBytes()));

        String checksumAddress ="";

        final char[] addrChars = address.toCharArray();
        final char[] addrHashChars = addressHash.toCharArray();

        for (int i = 0; i < addrChars.length; i++ ) {
            // If ith character is 9 to f then make it uppercase
            if (Integer.parseInt((addrHashChars[i]+""), 16) > 7) {
                checksumAddress += (addrChars[i] +"").toUpperCase();
            } else {
                checksumAddress += (addrChars[i] +"").toLowerCase();
            }
        }
        return "0x"+checksumAddress;
    }

    public static byte[] decodeAddressAsBytes(String address) {
        if (address == null) {
            return null;
        }
        address = address.trim();

        if (address.toLowerCase().startsWith("0x")) {
            address = address.substring(2);
        }

        if (address.length() == 42) {
            //probably this format 0xf8b483DbA2c3B7176a3Da549ad41A48BB3121069
            if (address.toLowerCase().startsWith("0x")) {
                address = address.substring(2);
            }
        }

        // verificar si es wallet de testnet
        if (address.length() == 40) {
            //probably this format f8b483DbA2c3B7176a3Da549ad41A48BB3121069
            if (isAllLowerCaseHex(address.toLowerCase())) {
                return hexStringToByteArray(address);
            }
        }
        return null;
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len/2];

        for(int i = 0; i < len; i+=2){
            data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static boolean isAllLowerCaseHex(String string) {
        final char[] chars = string.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            char c = chars[i];
            if (HEX_CHARS.indexOf(c) == -1) {
                return false;
            }
        }
        return true;
    }

    private static String bytesToHexString(byte[] bytes) {
        // http://stackoverflow.com/questions/332079
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
                sb.append('0');
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    @Override
    public boolean isAddressValid(String address) {
        return true;
    }

    @Override
    public boolean mustBeBase58Address() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isPaperWalletSupported() {
        // TODO Auto-generated method stub
        return false;
    }

}
