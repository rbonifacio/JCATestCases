package jca;

import java.security.SecureRandom;
import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
import test.UsagePatternTestingFramework;
import java.security.NoSuchProviderException;
import java.security.Provider;

public class SecureRandomTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void secureRandomValidTest1() throws NoSuchAlgorithmException {

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest2() throws NoSuchAlgorithmException, NoSuchProviderException {

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG", (Provider) null);
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest3() throws NoSuchAlgorithmException {

		SecureRandom secureRandom0 = SecureRandom.getInstanceStrong();
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest4() {

		SecureRandom secureRandom0 = new SecureRandom();
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest5() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom1.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom1);

		SecureRandom secureRandom0 = new SecureRandom(genSeed);
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest6() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom1.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom1);

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		secureRandom0.setSeed(genSeed);
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest7() throws NoSuchAlgorithmException, NoSuchProviderException {

		int num = 0;

		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom1.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom1);

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG", (Provider) null);
		secureRandom0.setSeed(genSeed);
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest8() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom1.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom1);

		SecureRandom secureRandom0 = SecureRandom.getInstanceStrong();
		secureRandom0.setSeed(genSeed);
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest9() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom1.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom1);

		SecureRandom secureRandom0 = new SecureRandom();
		secureRandom0.setSeed(genSeed);
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest10() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom1.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom1);

		SecureRandom secureRandom0 = new SecureRandom(genSeed);
		secureRandom0.setSeed(genSeed);
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest11() throws NoSuchAlgorithmException {

		long lSeed = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		secureRandom0.setSeed(lSeed);
		Assertions.hasEnsuredPredicate(secureRandom0);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest12() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest13() throws NoSuchAlgorithmException, NoSuchProviderException {

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG", (Provider) null);
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest14() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstanceStrong();
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest15() {

		int num = 0;

		SecureRandom secureRandom0 = new SecureRandom();
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest16() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom1.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom1);

		num = 0;

		SecureRandom secureRandom0 = new SecureRandom(genSeed);
		genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest17() throws NoSuchAlgorithmException {

		byte[] next = null;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		secureRandom0.nextBytes(next);
		Assertions.hasEnsuredPredicate(next);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest18() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom1.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom1);

		num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		secureRandom0.setSeed(genSeed);
		genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest19() throws NoSuchAlgorithmException, NoSuchProviderException {

		int num = 0;

		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom1.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom1);

		num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG", (Provider) null);
		secureRandom0.setSeed(genSeed);
		genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest20() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom1.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom1);

		num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstanceStrong();
		secureRandom0.setSeed(genSeed);
		genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest21() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom1.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom1);

		num = 0;

		SecureRandom secureRandom0 = new SecureRandom();
		secureRandom0.setSeed(genSeed);
		genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest22() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom1.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom1);

		num = 0;

		SecureRandom secureRandom0 = new SecureRandom(genSeed);
		secureRandom0.setSeed(genSeed);
		genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest23() throws NoSuchAlgorithmException {

		int num = 0;
		long lSeed = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		secureRandom0.setSeed(lSeed);
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}

	@Test
	public void secureRandomValidTest24() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom1 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom1.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom1);

		byte[] next = null;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		secureRandom0.setSeed(genSeed);
		secureRandom0.nextBytes(next);
		Assertions.hasEnsuredPredicate(next);
		Assertions.mustBeInAcceptingState(secureRandom0);

	}
}