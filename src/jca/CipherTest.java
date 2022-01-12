package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import javax.crypto.IllegalBlockSizeException;
import org.junit.Test;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.AlgorithmParameters;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import java.security.cert.Certificate;
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.security.InvalidKeyException;
import java.lang.String;
import javax.crypto.SecretKey;
import test.UsagePatternTestingFramework;
import java.security.NoSuchProviderException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.ShortBufferException;

public class CipherTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	
	@Test
	public void cipherValidTest1()
			throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException {

		Certificate cert = null;
		Key wrappedKey = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] wrappedKeyBytes = cipher0.wrap(wrappedKey);
		Assertions.hasEnsuredPredicate(wrappedKeyBytes);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest2() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			InvalidKeyException, NoSuchProviderException {

		Certificate cert = null;
		Key wrappedKey = null;

		Cipher cipher0 = Cipher.getInstance("RSA", (String) null);
		cipher0.init(1, cert);
		byte[] wrappedKeyBytes = cipher0.wrap(wrappedKey);
		Assertions.hasEnsuredPredicate(wrappedKeyBytes);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest3()
			throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException {

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		Certificate cert = null;
		Key wrappedKey = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert, secureRandom0);
		byte[] wrappedKeyBytes = cipher0.wrap(wrappedKey);
		Assertions.hasEnsuredPredicate(wrappedKeyBytes);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest4()
			throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		Key wrappedKey = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey);
		byte[] wrappedKeyBytes = cipher0.wrap(wrappedKey);
		Assertions.hasEnsuredPredicate(wrappedKeyBytes);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest5()
			throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		Key wrappedKey = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, secureRandom0);
		byte[] wrappedKeyBytes = cipher0.wrap(wrappedKey);
		Assertions.hasEnsuredPredicate(wrappedKeyBytes);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest6() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		GCMParameterSpec gCMParameterSpec0 = new GCMParameterSpec(96, genSeed);
		Assertions.hasEnsuredPredicate(gCMParameterSpec0);
		Assertions.mustBeInAcceptingState(gCMParameterSpec0);

		Key wrappedKey = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, gCMParameterSpec0);
		byte[] wrappedKeyBytes = cipher0.wrap(wrappedKey);
		Assertions.hasEnsuredPredicate(wrappedKeyBytes);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest7() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(dHGenParameterSpec0);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

		Key wrappedKey = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, algorithmParameters0);
		byte[] wrappedKeyBytes = cipher0.wrap(wrappedKey);
		Assertions.hasEnsuredPredicate(wrappedKeyBytes);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest8() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		GCMParameterSpec gCMParameterSpec0 = new GCMParameterSpec(96, genSeed);
		Assertions.hasEnsuredPredicate(gCMParameterSpec0);
		Assertions.mustBeInAcceptingState(gCMParameterSpec0);

		Key wrappedKey = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, gCMParameterSpec0, secureRandom0);
		byte[] wrappedKeyBytes = cipher0.wrap(wrappedKey);
		Assertions.hasEnsuredPredicate(wrappedKeyBytes);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest9() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(dHGenParameterSpec0);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		Key wrappedKey = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, algorithmParameters0, secureRandom0);
		byte[] wrappedKeyBytes = cipher0.wrap(wrappedKey);
		Assertions.hasEnsuredPredicate(wrappedKeyBytes);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest10() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException {

		Certificate cert = null;
		byte[] plainText = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest11() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

		Certificate cert = null;
		byte[] plainText = null;

		Cipher cipher0 = Cipher.getInstance("RSA", (String) null);
		cipher0.init(1, cert);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest12() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException {

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		Certificate cert = null;
		byte[] plainText = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert, secureRandom0);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest13() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		byte[] plainText = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest14() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		byte[] plainText = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, secureRandom0);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest15() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		GCMParameterSpec gCMParameterSpec0 = new GCMParameterSpec(96, genSeed);
		Assertions.hasEnsuredPredicate(gCMParameterSpec0);
		Assertions.mustBeInAcceptingState(gCMParameterSpec0);

		byte[] plainText = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, gCMParameterSpec0);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest16()
			throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(dHGenParameterSpec0);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

		byte[] plainText = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, algorithmParameters0);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest17() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		GCMParameterSpec gCMParameterSpec0 = new GCMParameterSpec(96, genSeed);
		Assertions.hasEnsuredPredicate(gCMParameterSpec0);
		Assertions.mustBeInAcceptingState(gCMParameterSpec0);

		byte[] plainText = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, gCMParameterSpec0, secureRandom0);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest18()
			throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(dHGenParameterSpec0);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		byte[] plainText = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, algorithmParameters0, secureRandom0);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest19() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException {

		int plain_off = 0;
		Certificate cert = null;
		byte[] plainText = null;
		int len = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] cipherText = cipher0.doFinal(plainText, plain_off, len);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest20() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		byte[] cipherText = null;
		int plain_off = 0;
		Certificate cert = null;
		byte[] plainText = null;
		int len = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		cipher0.doFinal(plainText, plain_off, len, cipherText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest21() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		byte[] cipherText = null;
		int plain_off = 0;
		Certificate cert = null;
		byte[] plainText = null;
		int len = 0;
		int ciphertext_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		cipher0.doFinal(plainText, plain_off, len, cipherText, ciphertext_off);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest22() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		ByteBuffer plainBuffer = null;
		Certificate cert = null;
		ByteBuffer cipherBuffer = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		cipher0.doFinal(plainBuffer, cipherBuffer);
		Assertions.hasEnsuredPredicate(cipherBuffer);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest23() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException {

		Certificate cert = null;
		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest24() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

		Certificate cert = null;
		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA", (String) null);
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest25() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException {

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		Certificate cert = null;
		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert, secureRandom0);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest26() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest27() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, secureRandom0);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest28() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		GCMParameterSpec gCMParameterSpec0 = new GCMParameterSpec(96, genSeed);
		Assertions.hasEnsuredPredicate(gCMParameterSpec0);
		Assertions.mustBeInAcceptingState(gCMParameterSpec0);

		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, gCMParameterSpec0);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest29()
			throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(dHGenParameterSpec0);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, algorithmParameters0);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest30() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		GCMParameterSpec gCMParameterSpec0 = new GCMParameterSpec(96, genSeed);
		Assertions.hasEnsuredPredicate(gCMParameterSpec0);
		Assertions.mustBeInAcceptingState(gCMParameterSpec0);

		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, gCMParameterSpec0, secureRandom0);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest31()
			throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(dHGenParameterSpec0);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, algorithmParameters0, secureRandom0);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest32() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException {

		Certificate cert = null;
		byte[] plainText = null;
		byte[] pre_plaintext = null;
		int pre_plain_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext, pre_plain_off, 0);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest33() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		Certificate cert = null;
		int pre_len = 0;
		byte[] plainText = null;
		byte[] pre_ciphertext = null;
		byte[] pre_plaintext = null;
		int pre_plain_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		cipher0.update(pre_plaintext, pre_plain_off, pre_len, pre_ciphertext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest34() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		int pre_ciphertext_off = 0;
		Certificate cert = null;
		int pre_len = 0;
		byte[] plainText = null;
		byte[] pre_ciphertext = null;
		byte[] pre_plaintext = null;
		int pre_plain_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		cipher0.update(pre_plaintext, pre_plain_off, pre_len, pre_ciphertext, pre_ciphertext_off);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest35() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		ByteBuffer pre_plainBuffer = null;
		Certificate cert = null;
		byte[] plainText = null;
		ByteBuffer pre_cipherBuffer = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		cipher0.update(pre_plainBuffer, pre_cipherBuffer);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest36() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException {

		int plain_off = 0;
		Certificate cert = null;
		byte[] plainText = null;
		int len = 0;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText, plain_off, len);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest37() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		byte[] cipherText = null;
		int plain_off = 0;
		Certificate cert = null;
		byte[] plainText = null;
		int len = 0;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		cipher0.doFinal(plainText, plain_off, len, cipherText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest38() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		byte[] cipherText = null;
		int plain_off = 0;
		Certificate cert = null;
		byte[] plainText = null;
		int len = 0;
		byte[] pre_plaintext = null;
		int ciphertext_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		cipher0.doFinal(plainText, plain_off, len, cipherText, ciphertext_off);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest39() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		ByteBuffer plainBuffer = null;
		Certificate cert = null;
		ByteBuffer cipherBuffer = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		cipher0.doFinal(plainBuffer, cipherBuffer);
		Assertions.hasEnsuredPredicate(cipherBuffer);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest40() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException {

		Certificate cert = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal();
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherValidTest41() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		byte[] cipherText = null;
		Certificate cert = null;
		byte[] pre_plaintext = null;
		int ciphertext_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		cipher0.doFinal(cipherText, ciphertext_off);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest1() throws NoSuchPaddingException, NoSuchAlgorithmException {

		Cipher cipher0 = Cipher.getInstance("RSA");
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest2() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {

		Cipher cipher0 = Cipher.getInstance("RSA", (String) null);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest3() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

		Certificate cert = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest4()
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

		Certificate cert = null;

		Cipher cipher0 = Cipher.getInstance("RSA", (String) null);
		cipher0.init(1, cert);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest5() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		Certificate cert = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert, secureRandom0);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest6() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest7() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, secureRandom0);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest8() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
			InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		GCMParameterSpec gCMParameterSpec0 = new GCMParameterSpec(96, genSeed);
		Assertions.hasEnsuredPredicate(gCMParameterSpec0);
		Assertions.mustBeInAcceptingState(gCMParameterSpec0);

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, gCMParameterSpec0);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest9() throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(dHGenParameterSpec0);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, algorithmParameters0);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest10() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
			InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		GCMParameterSpec gCMParameterSpec0 = new GCMParameterSpec(96, genSeed);
		Assertions.hasEnsuredPredicate(gCMParameterSpec0);
		Assertions.mustBeInAcceptingState(gCMParameterSpec0);

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, gCMParameterSpec0, secureRandom0);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest11() throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(dHGenParameterSpec0);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, algorithmParameters0, secureRandom0);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest12()
			throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException {

		Key wrappedKey = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		byte[] wrappedKeyBytes = cipher0.wrap(wrappedKey);
		Assertions.notHasEnsuredPredicate(wrappedKeyBytes);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest13() throws NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

		Key wrappedKey = null;

		Cipher cipher0 = Cipher.getInstance("RSA", (String) null);
		byte[] wrappedKeyBytes = cipher0.wrap(wrappedKey);
		Assertions.notHasEnsuredPredicate(wrappedKeyBytes);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest14()
			throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException {

		byte[] plainText = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest15() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, NoSuchProviderException {

		byte[] plainText = null;

		Cipher cipher0 = Cipher.getInstance("RSA", (String) null);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest16()
			throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException {

		int plain_off = 0;
		byte[] plainText = null;
		int len = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		byte[] cipherText = cipher0.doFinal(plainText, plain_off, len);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest17() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, ShortBufferException {

		byte[] cipherText = null;
		int plain_off = 0;
		byte[] plainText = null;
		int len = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.doFinal(plainText, plain_off, len, cipherText);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest18() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, ShortBufferException {

		byte[] cipherText = null;
		int plain_off = 0;
		byte[] plainText = null;
		int len = 0;
		int ciphertext_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.doFinal(plainText, plain_off, len, cipherText, ciphertext_off);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest19() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, ShortBufferException {

		ByteBuffer plainBuffer = null;
		ByteBuffer cipherBuffer = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.doFinal(plainBuffer, cipherBuffer);
		Assertions.notHasEnsuredPredicate(cipherBuffer);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest20() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

		Certificate cert = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		Assertions.hasEnsuredPredicate(pre_ciphertext);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest21()
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

		Certificate cert = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA", (String) null);
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		Assertions.hasEnsuredPredicate(pre_ciphertext);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest22() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		Certificate cert = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert, secureRandom0);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		Assertions.hasEnsuredPredicate(pre_ciphertext);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest23() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		Assertions.hasEnsuredPredicate(pre_ciphertext);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest24() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, secureRandom0);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		Assertions.hasEnsuredPredicate(pre_ciphertext);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest25() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
			InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		GCMParameterSpec gCMParameterSpec0 = new GCMParameterSpec(96, genSeed);
		Assertions.hasEnsuredPredicate(gCMParameterSpec0);
		Assertions.mustBeInAcceptingState(gCMParameterSpec0);

		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, gCMParameterSpec0);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		Assertions.hasEnsuredPredicate(pre_ciphertext);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest26() throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(dHGenParameterSpec0);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, algorithmParameters0);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		Assertions.hasEnsuredPredicate(pre_ciphertext);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest27() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
			InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		GCMParameterSpec gCMParameterSpec0 = new GCMParameterSpec(96, genSeed);
		Assertions.hasEnsuredPredicate(gCMParameterSpec0);
		Assertions.mustBeInAcceptingState(gCMParameterSpec0);

		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, gCMParameterSpec0, secureRandom0);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		Assertions.hasEnsuredPredicate(pre_ciphertext);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest28() throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidParameterSpecException, InvalidKeyException, InvalidAlgorithmParameterException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(dHGenParameterSpec0);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, secretKey, algorithmParameters0, secureRandom0);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		Assertions.hasEnsuredPredicate(pre_ciphertext);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest29() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

		Certificate cert = null;
		byte[] pre_plaintext = null;
		int pre_plain_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext, pre_plain_off, 0);
		Assertions.hasEnsuredPredicate(pre_ciphertext);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest30()
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		Certificate cert = null;
		int pre_len = 0;
		byte[] pre_ciphertext = null;
		byte[] pre_plaintext = null;
		int pre_plain_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		cipher0.update(pre_plaintext, pre_plain_off, pre_len, pre_ciphertext);
		Assertions.hasEnsuredPredicate(pre_ciphertext);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest31()
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		int pre_ciphertext_off = 0;
		Certificate cert = null;
		int pre_len = 0;
		byte[] pre_ciphertext = null;
		byte[] pre_plaintext = null;
		int pre_plain_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		cipher0.update(pre_plaintext, pre_plain_off, pre_len, pre_ciphertext, pre_ciphertext_off);
		Assertions.hasEnsuredPredicate(pre_ciphertext);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest32()
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		ByteBuffer pre_plainBuffer = null;
		Certificate cert = null;
		ByteBuffer pre_cipherBuffer = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		cipher0.update(pre_plainBuffer, pre_cipherBuffer);
		Assertions.hasEnsuredPredicate(pre_ciphertext);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest33()
			throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException {

		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest34() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, NoSuchProviderException {

		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA", (String) null);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest35()
			throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException {

		byte[] plainText = null;
		byte[] pre_plaintext = null;
		int pre_plain_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		byte[] pre_ciphertext = cipher0.update(pre_plaintext, pre_plain_off, 0);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest36() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, ShortBufferException {

		int pre_len = 0;
		byte[] plainText = null;
		byte[] pre_ciphertext = null;
		byte[] pre_plaintext = null;
		int pre_plain_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.update(pre_plaintext, pre_plain_off, pre_len, pre_ciphertext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest37() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, ShortBufferException {

		int pre_ciphertext_off = 0;
		int pre_len = 0;
		byte[] plainText = null;
		byte[] pre_ciphertext = null;
		byte[] pre_plaintext = null;
		int pre_plain_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.update(pre_plaintext, pre_plain_off, pre_len, pre_ciphertext, pre_ciphertext_off);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest38() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, ShortBufferException {

		ByteBuffer pre_plainBuffer = null;
		byte[] plainText = null;
		ByteBuffer pre_cipherBuffer = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.update(pre_plainBuffer, pre_cipherBuffer);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest39()
			throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException {

		int plain_off = 0;
		byte[] plainText = null;
		int len = 0;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText, plain_off, len);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest40() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, ShortBufferException {

		byte[] cipherText = null;
		int plain_off = 0;
		byte[] plainText = null;
		int len = 0;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		cipher0.doFinal(plainText, plain_off, len, cipherText);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest41() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, ShortBufferException {

		byte[] cipherText = null;
		int plain_off = 0;
		byte[] plainText = null;
		int len = 0;
		byte[] pre_plaintext = null;
		int ciphertext_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		cipher0.doFinal(plainText, plain_off, len, cipherText, ciphertext_off);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest42() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, ShortBufferException {

		ByteBuffer plainBuffer = null;
		ByteBuffer cipherBuffer = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		cipher0.doFinal(plainBuffer, cipherBuffer);
		Assertions.notHasEnsuredPredicate(cipherBuffer);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest43()
			throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException {

		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal();
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}

	@Test
	public void cipherInvalidTest44() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException,
			NoSuchAlgorithmException, ShortBufferException {

		byte[] cipherText = null;
		byte[] pre_plaintext = null;
		int ciphertext_off = 0;

		Cipher cipher0 = Cipher.getInstance("RSA");
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		cipher0.doFinal(cipherText, ciphertext_off);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(cipher0);

	}
}