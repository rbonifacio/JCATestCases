package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import java.security.spec.InvalidKeySpecException;
import org.junit.Test;
import java.security.SecureRandom;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.SecretKey;
import java.lang.String;
import test.UsagePatternTestingFramework;
import java.security.NoSuchProviderException;

public class SecretKeyFactoryTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void secretKeyFactoryValidTest1() throws InvalidKeySpecException, NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		int keylength = 0;
		char[] password = null;

		PBEKeySpec pBEKeySpec0 = new PBEKeySpec(password, genSeed, 22712, keylength);
		Assertions.hasEnsuredPredicate(pBEKeySpec0);

		SecretKeyFactory secretKeyFactory0 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		SecretKey secretKey = secretKeyFactory0.generateSecret(pBEKeySpec0);
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(secretKeyFactory0);
		pBEKeySpec0.clearPassword();
		Assertions.mustBeInAcceptingState(pBEKeySpec0);

	}

	@Test
	public void secretKeyFactoryValidTest2()
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		int keylength = 0;
		char[] password = null;

		PBEKeySpec pBEKeySpec0 = new PBEKeySpec(password, genSeed, 25888, keylength);
		Assertions.hasEnsuredPredicate(pBEKeySpec0);

		SecretKeyFactory secretKeyFactory0 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", (String) null);
		SecretKey secretKey = secretKeyFactory0.generateSecret(pBEKeySpec0);
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(secretKeyFactory0);
		pBEKeySpec0.clearPassword();
		Assertions.mustBeInAcceptingState(pBEKeySpec0);

	}

	@Test
	public void secretKeyFactoryValidTest3() throws NoSuchAlgorithmException, InvalidKeyException {

		SecretKey otherKey = null;

		SecretKeyFactory secretKeyFactory0 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		SecretKey secretKey = secretKeyFactory0.translateKey(otherKey);
		Assertions.hasEnsuredPredicate(secretKey);
		Assertions.mustBeInAcceptingState(secretKeyFactory0);

	}

	@Test
	public void secretKeyFactoryInvalidTest1() throws NoSuchAlgorithmException {

		SecretKeyFactory secretKeyFactory0 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		Assertions.mustNotBeInAcceptingState(secretKeyFactory0);

	}

	@Test
	public void secretKeyFactoryInvalidTest2() throws NoSuchAlgorithmException, NoSuchProviderException {

		SecretKeyFactory secretKeyFactory0 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", (String) null);
		Assertions.mustNotBeInAcceptingState(secretKeyFactory0);

	}
}