package net.unit8.cryptoutils;

/**
 * The crypt context.
 *
 * @author kawasima
 */
public class CryptoContext {
    private String algorithm = "AES";
    private String mode = "CBC";
    private String padding = "PKCS5Padding";

    private byte[] key;
    private Integer keysize;
    private byte[] iv;

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public int getKeySize() {
        if (keysize == null && "AES".equals(algorithm)) {
            return 256;
        } else {
            return (keysize == null) ? 0 : keysize;
        }
    }

    public void setKeySize(int keysize) {
        this.keysize = keysize;
    }

    public byte[] getIV() {
        return iv;
    }

    public void setIV(byte[] iv) {
        this.iv = iv;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String getPadding() {
        return padding;
    }

    public void setPadding(String padding) {
        this.padding = padding;
    }
}
