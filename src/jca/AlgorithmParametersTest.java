package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import javax.crypto.spec.DHGenParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import org.junit.Test;
import java.io.IOException;
import java.lang.String;
import test.UsagePatternTestingFramework;
import java.security.NoSuchProviderException;
import java.security.AlgorithmParameters;
import java.security.Provider;

public class AlgorithmParametersTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void algorithmParametersValidTest1() throws NoSuchAlgorithmException, InvalidParameterSpecException {

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(dHGenParameterSpec0);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

	}

	@Test
	public void algorithmParametersValidTest2()
			throws NoSuchAlgorithmException, InvalidParameterSpecException, NoSuchProviderException {

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES", (Provider) null);
		algorithmParameters0.init(dHGenParameterSpec0);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

	}

	@Test
	public void algorithmParametersValidTest3()
			throws NoSuchAlgorithmException, InvalidParameterSpecException, IOException {

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters1 = AlgorithmParameters.getInstance("AES");
		algorithmParameters1.init(dHGenParameterSpec0);
		byte[] parsRes = algorithmParameters1.getEncoded();
		Assertions.hasEnsuredPredicate(parsRes);
		Assertions.mustBeInAcceptingState(algorithmParameters1);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(parsRes);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

	}

	@Test
	public void algorithmParametersValidTest4()
			throws NoSuchAlgorithmException, InvalidParameterSpecException, IOException {

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters1 = AlgorithmParameters.getInstance("AES");
		algorithmParameters1.init(dHGenParameterSpec0);
		byte[] parsRes = algorithmParameters1.getEncoded();
		Assertions.hasEnsuredPredicate(parsRes);
		Assertions.mustBeInAcceptingState(algorithmParameters1);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(parsRes, (String) null);
		Assertions.hasEnsuredPredicate(algorithmParameters0);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

	}

	@Test
	public void algorithmParametersValidTest5()
			throws NoSuchAlgorithmException, InvalidParameterSpecException, IOException {

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(dHGenParameterSpec0);
		byte[] parsRes = algorithmParameters0.getEncoded();
		Assertions.hasEnsuredPredicate(parsRes);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

	}

	@Test
	public void algorithmParametersValidTest6()
			throws NoSuchAlgorithmException, InvalidParameterSpecException, IOException, NoSuchProviderException {

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES", (Provider) null);
		algorithmParameters0.init(dHGenParameterSpec0);
		byte[] parsRes = algorithmParameters0.getEncoded();
		Assertions.hasEnsuredPredicate(parsRes);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

	}

	@Test
	public void algorithmParametersValidTest7()
			throws NoSuchAlgorithmException, InvalidParameterSpecException, IOException {

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters1 = AlgorithmParameters.getInstance("AES");
		algorithmParameters1.init(dHGenParameterSpec0);
		byte[] parsRes = algorithmParameters1.getEncoded();
		Assertions.hasEnsuredPredicate(parsRes);
		Assertions.mustBeInAcceptingState(algorithmParameters1);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(parsRes);
		parsRes = algorithmParameters0.getEncoded();
		Assertions.hasEnsuredPredicate(parsRes);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

	}

	@Test
	public void algorithmParametersValidTest8()
			throws NoSuchAlgorithmException, InvalidParameterSpecException, IOException {

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		AlgorithmParameters algorithmParameters1 = AlgorithmParameters.getInstance("AES");
		algorithmParameters1.init(dHGenParameterSpec0);
		byte[] parsRes = algorithmParameters1.getEncoded();
		Assertions.hasEnsuredPredicate(parsRes);
		Assertions.mustBeInAcceptingState(algorithmParameters1);

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(parsRes, (String) null);
		parsRes = algorithmParameters0.getEncoded();
		Assertions.hasEnsuredPredicate(parsRes);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

	}

	@Test
	public void algorithmParametersValidTest9()
			throws NoSuchAlgorithmException, InvalidParameterSpecException, IOException {

		int exponentSize = 0;
		int primeSize = 0;

		DHGenParameterSpec dHGenParameterSpec0 = new DHGenParameterSpec(primeSize, exponentSize);
		Assertions.hasEnsuredPredicate(dHGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dHGenParameterSpec0);

		String format = null;

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		algorithmParameters0.init(dHGenParameterSpec0);
		byte[] parsRes = algorithmParameters0.getEncoded(format);
		Assertions.hasEnsuredPredicate(parsRes);
		Assertions.mustBeInAcceptingState(algorithmParameters0);

	}

	@Test
	public void algorithmParametersInvalidTest1() throws NoSuchAlgorithmException {

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		Assertions.notHasEnsuredPredicate(algorithmParameters0);
		Assertions.mustNotBeInAcceptingState(algorithmParameters0);

	}

	@Test
	public void algorithmParametersInvalidTest2() throws NoSuchAlgorithmException, NoSuchProviderException {

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES", (Provider) null);
		Assertions.notHasEnsuredPredicate(algorithmParameters0);
		Assertions.mustNotBeInAcceptingState(algorithmParameters0);

	}

	@Test
	public void algorithmParametersInvalidTest3() throws NoSuchAlgorithmException, IOException {

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		byte[] parsRes = algorithmParameters0.getEncoded();
		Assertions.notHasEnsuredPredicate(parsRes);
		Assertions.mustNotBeInAcceptingState(algorithmParameters0);

	}

	@Test
	public void algorithmParametersInvalidTest4()
			throws NoSuchAlgorithmException, IOException, NoSuchProviderException {

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES", (Provider) null);
		byte[] parsRes = algorithmParameters0.getEncoded();
		Assertions.notHasEnsuredPredicate(parsRes);
		Assertions.mustNotBeInAcceptingState(algorithmParameters0);

	}

	@Test
	public void algorithmParametersInvalidTest5() throws NoSuchAlgorithmException, IOException {

		String format = null;

		AlgorithmParameters algorithmParameters0 = AlgorithmParameters.getInstance("AES");
		byte[] parsRes = algorithmParameters0.getEncoded(format);
		Assertions.notHasEnsuredPredicate(parsRes);
		Assertions.mustNotBeInAcceptingState(algorithmParameters0);

	}
}