package io.github.andylke.demo;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

@SpringBootApplication
public class DemoApplication {

  public static void main(String[] args) {
    SpringApplication.run(DemoApplication.class, args);
  }

  @EventListener(ApplicationReadyEvent.class)
  void ready() throws Exception {
    encrypt(generateSecretKey(128));
    encrypt(generateSecretKey(192));
    encrypt(generateSecretKey(256));

    encrypt(secretKeySpec("1234567890123456"));
    encrypt(secretKeySpec("123456789012345678901234"));
    encrypt(secretKeySpec("12345678901234567890123456789012"));
  }

  private SecretKey secretKeySpec(final String secretKeyString) {
    final byte[] secretKeyBytes = secretKeyString.getBytes();

    final SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES");

    String base64String = Base64.getEncoder().encodeToString(secretKeyBytes);
    System.out.println(
        "Custom secretKey base64String=["
            + base64String
            + "], length=["
            + secretKeyBytes.length
            + "]");

    return secretKey;
  }

  private SecretKey generateSecretKey(final int keySize) throws NoSuchAlgorithmException {
    final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(keySize);
    final SecretKey secretKey = keyGenerator.generateKey();

    final byte[] secretKeyBytes = secretKey.getEncoded();

    String base64String = Base64.getEncoder().encodeToString(secretKeyBytes);
    System.out.println(
        "Generated secretKey base64String=["
            + base64String
            + "], length=["
            + secretKeyBytes.length
            + "] using keySize=["
            + keySize
            + "]");

    return secretKey;
  }

  private void encrypt(final SecretKey secretKey)
      throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
          InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    // Encrypt Hello world message
    Cipher encryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    IvParameterSpec parameterSpec = new IvParameterSpec(new byte[16]);
    encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
    String message = "Hello world";

    byte[] encryptedMessageBytes = encryptionCipher.doFinal(message.getBytes());
    String encryptedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);
    System.out.println("Encrypted message = " + encryptedMessage);
  }
}
