package jca;

import java.security.SecureRandom;
import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
import javax.crypto.SecretKey;
import java.security.spec.AlgorithmParameterSpec;
import test.UsagePatternTestingFramework;
import java.security.NoSuchProviderException;
import javax.crypto.KeyGenerator;
import java.security.Provider;
import java.security.InvalidAlgorithmParameterException;

public class KeyGeneratorTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void keyGeneratorValidTest1() throws NoSuchAlgorithmException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorValidTest2() throws NoSuchAlgorithmException, NoSuchProviderException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES", (Provider) null);
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorValidTest3() throws NoSuchAlgorithmException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		keyGenerator0.init(128);
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorValidTest4() throws NoSuchAlgorithmException, NoSuchProviderException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES", (Provider) null);
		keyGenerator0.init(128);
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorValidTest5() throws NoSuchAlgorithmException {

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		keyGenerator0.init(128, secureRandom0);
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorValidTest6() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		AlgorithmParameterSpec params = null;

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		keyGenerator0.init(params);
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorValidTest7() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		AlgorithmParameterSpec params = null;

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		keyGenerator0.init(params, secureRandom0);
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorValidTest8() throws NoSuchAlgorithmException {

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		keyGenerator0.init(secureRandom0);
		SecretKey secretKey = keyGenerator0.generateKey();
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorInvalidTest1() throws NoSuchAlgorithmException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		Assertions.mustNotBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorInvalidTest2() throws NoSuchAlgorithmException, NoSuchProviderException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES", (Provider) null);
		Assertions.mustNotBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorInvalidTest3() throws NoSuchAlgorithmException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		keyGenerator0.init(128);
		Assertions.mustNotBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorInvalidTest4() throws NoSuchAlgorithmException, NoSuchProviderException {

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES", (Provider) null);
		keyGenerator0.init(128);
		Assertions.mustNotBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorInvalidTest5() throws NoSuchAlgorithmException {

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		keyGenerator0.init(128, secureRandom0);
		Assertions.mustNotBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorInvalidTest6() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		AlgorithmParameterSpec params = null;

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		keyGenerator0.init(params);
		Assertions.mustNotBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorInvalidTest7() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		AlgorithmParameterSpec params = null;

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		keyGenerator0.init(params, secureRandom0);
		Assertions.mustNotBeInAcceptingState(keyGenerator0);

	}

	@Test
	public void keyGeneratorInvalidTest8() throws NoSuchAlgorithmException {

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

		KeyGenerator keyGenerator0 = KeyGenerator.getInstance("AES");
		keyGenerator0.init(secureRandom0);
		Assertions.mustNotBeInAcceptingState(keyGenerator0);

	}
}