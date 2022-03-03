package io.github.andylke.demo;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
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
    final String clearHexString =
        "f0f8f1f0e2e2f8f6f9f0f4404040404040404040404040404040f0f0c5e3d7d4c2e240404040404040404040404040404040404040404040404040404040404040404040404040404040f3f5c5d54040f0f0f0f0f1e3c3c8c3f2f9f5404040404040404040404040404040404040404040404040404040404040404040c940404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040f0f0f0f0f0f0f0f0f040404040404040404040404040404040f0f2f0d5c6f0f0f0f160f0f160f0f160f0f04bf0f04bf0f04bf0f0f0f0f0f04040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040e2c74040404040404040404040f0f0f0f0f0f0f0f0f0404040404040404040404040404040404040e3c3c8c3f2f9f5404040";
    final SecretKey secretKeySpec =
        secretKeySpec("2c10253c02052e0331692e4a204b704204135c1e30336f6d13026f00604b0072");

    final String encryptedHexString =
        encrypt(secretKeySpec, ivParameterSpec("f0f0f0f0f04040404040404040404040"), clearHexString);

    final String ivHexString =
        encrypt(
            secretKeySpec, new IvParameterSpec(new byte[16]), "f0f0f0f0f04040404040404040404040");
    final byte[] ivHexBytes = ByteUtils.fromHexString(ivHexString);
    final byte[] ivHex16Bytes = new byte[16];
    System.arraycopy(ivHexBytes, 0, ivHex16Bytes, 0, 16);
    IvParameterSpec ivParameterSPec = ivParameterSpec(ByteUtils.toHexString(ivHex16Bytes));

    decrypt(secretKeySpec, ivParameterSPec, encryptedHexString);
  }

  private SecretKey secretKeySpec(final String secretKeyHexString) {
    final byte[] secretKeyBytes = ByteUtils.fromHexString(secretKeyHexString);
    return new SecretKeySpec(secretKeyBytes, "AES");
  }

  private IvParameterSpec ivParameterSpec(String ivParameterSpecHexString) {
    final byte[] ivParameterBytes = ByteUtils.fromHexString(ivParameterSpecHexString);

    return new IvParameterSpec(ivParameterBytes);
  }

  private String encrypt(
      final SecretKey secretKey,
      final IvParameterSpec ivParameterSpec,
      final String clearContentHexString)
      throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
          InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

    final byte[] clearContentBytes = ByteUtils.fromHexString(clearContentHexString);
    byte[] encryptedBytes = cipher.doFinal(clearContentBytes);
    String encryptedHexString = ByteUtils.toHexString(encryptedBytes);
    System.out.println("Encrypt IV = " + ByteUtils.toHexString(ivParameterSpec.getIV()));
    System.out.println("Encrypted = " + encryptedHexString);

    return encryptedHexString;
  }

  private String decrypt(
      final SecretKey secretKey,
      final IvParameterSpec ivParameterSpec,
      final String encryptedHexString)
      throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
          InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

    final byte[] encryptedBytes = ByteUtils.fromHexString(encryptedHexString);
    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
    String decryptedHexString = ByteUtils.toHexString(decryptedBytes);
    System.out.println("Decrypt IV = " + ByteUtils.toHexString(ivParameterSpec.getIV()));
    System.out.println("Decrypted = " + decryptedHexString);

    return decryptedHexString;
  }
}
