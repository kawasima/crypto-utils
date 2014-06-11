package net.unit8.cryptoutils;

import org.apache.commons.io.IOUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * The utilities of encrypt/decrypt files
 *
 * @author kawasima
 */
public class FileCryptoUtils {
    private static SecretKey generateKey(CryptoContext context) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(context.getAlgorithm());
            if (context.getKeySize() == 0) {
                kg.init(new SecureRandom());
            } else {
                kg.init(context.getKeySize(), new SecureRandom());
            }
            SecretKey key = kg.generateKey();
            context.setKey(key.getEncoded());
            return key;
        } catch(NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static Cipher createCipher(String algorithm) {
        try {
            return Cipher.getInstance(algorithm);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static void swapFile(Path src, Path dest) throws IOException {
        Path backup = dest.getParent().resolve(dest.getFileName() + ".bak");
        try {
            Files.move(dest, backup);
            Files.deleteIfExists(dest);
            Files.move(src, dest);
            Files.deleteIfExists(backup);
        } catch (IOException ex) {
            if (Files.exists(backup)) {
                Files.deleteIfExists(dest);
                Files.move(backup, dest);
            }
        }
    }

    public static CryptoContext encrypt(File target, CryptoContext context) throws IOException, GeneralSecurityException {
        if (context.getAlgorithm() == null)
            throw new NoSuchAlgorithmException("Algorithm is null");
        SecretKey key = (context.getKey() == null) ?
                generateKey(context) :
                new SecretKeySpec(context.getKey(), context.getAlgorithm());

        Cipher c = createCipher(context.getAlgorithm() + "/" + context.getMode() +"/" + context.getPadding());
        if (context.getIV() == null) {
            c.init(Cipher.ENCRYPT_MODE, key);
            context.setIV(c.getIV());
        } else {
            c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(context.getIV()));
        }

        CipherOutputStream cos = null;
        FileInputStream fis = null;
        Path tempdir = Files.createTempDirectory("encryptor");
        Path tempfile = null;

        try {
            tempfile = Files.createTempFile(tempdir, "enc", ".tmp");
            cos = new CipherOutputStream(
                    Files.newOutputStream(tempfile, StandardOpenOption.DELETE_ON_CLOSE), c);
            fis = new FileInputStream(target);
            IOUtils.copy(fis, cos);
        } finally {
            IOUtils.closeQuietly(fis);
            IOUtils.closeQuietly(cos);
            Files.deleteIfExists(tempdir);
        }
        swapFile(tempfile, target.toPath());
        return context;
    }

    public static void decrypt(File target, CryptoContext context) throws IOException, GeneralSecurityException {
        if (context.getAlgorithm() == null)
            throw new NoSuchAlgorithmException("Algorithm is null");
        if (context.getKey() == null)
            throw new InvalidKeyException("Key must not be empty in decrypt.");

        SecretKey key = new SecretKeySpec(context.getKey(), context.getAlgorithm());
        Cipher c = createCipher(context.getAlgorithm() + "/" + context.getMode() + "/" + context.getPadding());

        if(context.getIV() == null) {
            c.init(Cipher.DECRYPT_MODE, key);
        } else {
            c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(context.getIV()));
        }

        CipherInputStream cis = null;
        OutputStream fos = null;
        Path tempdir = Files.createTempDirectory("decryptor");
        Path tempfile = null;
        try {
            tempfile = Files.createTempFile(tempdir, "dec", ".tmp");
            cis = new CipherInputStream(new FileInputStream(target), c);
            fos = Files.newOutputStream(tempfile, StandardOpenOption.DELETE_ON_CLOSE);
            IOUtils.copy(cis, fos);
        } finally {
            IOUtils.closeQuietly(fos);
            IOUtils.closeQuietly(cis);
            Files.deleteIfExists(tempdir);
        }
        swapFile(tempfile, target.toPath());
    }

}
