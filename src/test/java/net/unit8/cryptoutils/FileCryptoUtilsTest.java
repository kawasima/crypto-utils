package net.unit8.cryptoutils;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 * Test for FileCryptoUtils.
 *
 * @author kawasima
 */
public class FileCryptoUtilsTest {
    private Path targetFile;
    @Before
    public void setUp() throws IOException {
        targetFile = Paths.get("target", "test.txt");
        Files.deleteIfExists(targetFile);
        Files.createFile(targetFile);

        Files.write(targetFile,
                Arrays.asList("hoge", "fuga"),
                Charset.forName("UTF-8"));
    }

    @Test
    public void AES_CBC_PKCS5Padding() throws Exception {
        long t1 = System.currentTimeMillis();
        CryptoContext context = new CryptoContext();
        FileCryptoUtils.encrypt(targetFile.toFile(), context);
        System.out.println((System.currentTimeMillis() - t1) + "ms; "
                + context.getKey());
        System.out.println(Arrays.asList(context.getIV()));
        long t2 = System.currentTimeMillis();
        FileCryptoUtils.decrypt(targetFile.toFile(), context);
        System.out.println((System.currentTimeMillis() - t2) + "ms; "
                + context.getKey());
        List<String> lines =  Files.readAllLines(targetFile, Charset.forName("UTF-8"));
        Assert.assertArrayEquals(
                new String[]{"hoge", "fuga"},
                lines.toArray(new String[lines.size()]));
    }

    @Test
    public void noAlgorithm() {
        CryptoContext context = new CryptoContext();
        context.setAlgorithm(null);

        try {
            FileCryptoUtils.encrypt(targetFile.toFile(), context);
            Assert.fail("We expect NoSuchAlgorithmException occur.");
        } catch(GeneralSecurityException ex) {
            Assert.assertTrue(ex instanceof NoSuchAlgorithmException);
        } catch(Exception ex) {
            Assert.fail("Unexpected exception occurred." + ex);
        }
    }

    @Test
    public void tripleDES_ECB_PKCS5Padding() throws GeneralSecurityException, IOException{
        long t1 = System.currentTimeMillis();
        CryptoContext context = new CryptoContext();
        context.setAlgorithm("DESede");
        context.setMode("ECB");
        FileCryptoUtils.encrypt(targetFile.toFile(), context);
        System.out.println((System.currentTimeMillis() - t1) + "ms; "
                + context.getKey());
        System.out.println(Arrays.asList(context.getIV()));
        long t2 = System.currentTimeMillis();
        FileCryptoUtils.decrypt(targetFile.toFile(), context);
        System.out.println((System.currentTimeMillis() - t2) + "ms; "
                + context.getKey());
        List<String> lines =  Files.readAllLines(targetFile, Charset.forName("UTF-8"));
        Assert.assertArrayEquals(
                new String[]{"hoge", "fuga"},
                lines.toArray(new String[lines.size()]));
    }
}
