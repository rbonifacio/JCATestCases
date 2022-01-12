package jca;

import java.lang.IllegalStateException;
import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import org.junit.Test;
import javax.crypto.Cipher;
import java.security.Provider;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import javax.crypto.BadPaddingException;
import java.security.cert.Certificate;
import javax.xml.crypto.dsig.spec.HMACParameterSpec;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import test.UsagePatternTestingFramework;
import java.security.NoSuchProviderException;
import javax.crypto.ShortBufferException;

public class MacTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void macValidTest1() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {

		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		byte[] output1 = mac0.doFinal();
		Assertions.hasEnsuredPredicate(output1);
		Assertions.mustBeInAcceptingState(mac0);

	}

	@Test
	public void macValidTest2()
			throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5", (Provider) null);
		mac0.init(key);
		byte[] output1 = mac0.doFinal();
		Assertions.hasEnsuredPredicate(output1);
		Assertions.mustBeInAcceptingState(mac0);

	}

	@Test
	public void macValidTest3() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException,
			InvalidAlgorithmParameterException {

		int outputLength = 0;

		HMACParameterSpec hMACParameterSpec0 = new HMACParameterSpec(outputLength);
		Assertions.hasEnsuredPredicate(hMACParameterSpec0);
		Assertions.mustBeInAcceptingState(hMACParameterSpec0);

		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key, hMACParameterSpec0);
		byte[] output1 = mac0.doFinal();
		Assertions.hasEnsuredPredicate(output1);
		Assertions.mustBeInAcceptingState(mac0);

	}

	@Test
	public void macValidTest4() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {

		byte[] input = null;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		byte[] output2 = mac0.doFinal(input);
		Assertions.hasEnsuredPredicate(output2);
		Assertions.mustBeInAcceptingState(mac0);

	}

	@Test
	public void macValidTest5() throws IllegalStateException, BadPaddingException, NoSuchPaddingException,
			IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		Certificate cert = null;
		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

		int outOffset = 0;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		mac0.doFinal(cipherText, outOffset);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(mac0);

	}

	@Test
	public void macValidTest6() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {

		byte inp = 0;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		mac0.update(inp);
		byte[] output1 = mac0.doFinal();
		Assertions.hasEnsuredPredicate(output1);
		Assertions.mustBeInAcceptingState(mac0);

	}

	@Test
	public void macValidTest7()
			throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

		byte inp = 0;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5", (Provider) null);
		mac0.init(key);
		mac0.update(inp);
		byte[] output1 = mac0.doFinal();
		Assertions.hasEnsuredPredicate(output1);
		Assertions.mustBeInAcceptingState(mac0);

	}

	@Test
	public void macValidTest8() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException,
			InvalidAlgorithmParameterException {

		int outputLength = 0;

		HMACParameterSpec hMACParameterSpec0 = new HMACParameterSpec(outputLength);
		Assertions.hasEnsuredPredicate(hMACParameterSpec0);
		Assertions.mustBeInAcceptingState(hMACParameterSpec0);

		byte inp = 0;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key, hMACParameterSpec0);
		mac0.update(inp);
		byte[] output1 = mac0.doFinal();
		Assertions.hasEnsuredPredicate(output1);
		Assertions.mustBeInAcceptingState(mac0);

	}

	@Test
	public void macValidTest9() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {

		byte[] pre_input = null;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		mac0.update(pre_input);
		byte[] output1 = mac0.doFinal();
		Assertions.hasEnsuredPredicate(output1);
		Assertions.mustBeInAcceptingState(mac0);

	}

	@Test
	public void macValidTest10() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {

		int offset = 0;
		int len = 0;
		byte[] pre_input = null;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		mac0.update(pre_input, offset, len);
		byte[] output1 = mac0.doFinal();
		Assertions.hasEnsuredPredicate(output1);
		Assertions.mustBeInAcceptingState(mac0);

	}

	@Test
	public void macValidTest11() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {

		byte[] pre_input = null;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		mac0.update(pre_input);
		byte[] output1 = mac0.doFinal();
		Assertions.hasEnsuredPredicate(output1);
		Assertions.mustBeInAcceptingState(mac0);

	}

	@Test
	public void macValidTest12() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {

		byte[] input = null;
		byte inp = 0;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		mac0.update(inp);
		byte[] output2 = mac0.doFinal(input);
		Assertions.hasEnsuredPredicate(output2);
		Assertions.mustBeInAcceptingState(mac0);

	}

	@Test
	public void macValidTest13() throws IllegalStateException, BadPaddingException, NoSuchPaddingException,
			IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		Certificate cert = null;
		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

		int outOffset = 0;
		byte inp = 0;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		mac0.update(inp);
		mac0.doFinal(cipherText, outOffset);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest1() throws NoSuchAlgorithmException {

		Mac mac0 = Mac.getInstance("HmacMD5");
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest2() throws NoSuchAlgorithmException, NoSuchProviderException {

		Mac mac0 = Mac.getInstance("HmacMD5", (Provider) null);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest3() throws NoSuchAlgorithmException, InvalidKeyException {

		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest4() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5", (Provider) null);
		mac0.init(key);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest5()
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {

		int outputLength = 0;

		HMACParameterSpec hMACParameterSpec0 = new HMACParameterSpec(outputLength);
		Assertions.hasEnsuredPredicate(hMACParameterSpec0);
		Assertions.mustBeInAcceptingState(hMACParameterSpec0);

		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key, hMACParameterSpec0);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest6() throws IllegalStateException, NoSuchAlgorithmException {

		Mac mac0 = Mac.getInstance("HmacMD5");
		byte[] output1 = mac0.doFinal();
		Assertions.notHasEnsuredPredicate(output1);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest7() throws IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {

		Mac mac0 = Mac.getInstance("HmacMD5", (Provider) null);
		byte[] output1 = mac0.doFinal();
		Assertions.notHasEnsuredPredicate(output1);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest8() throws IllegalStateException, NoSuchAlgorithmException {

		byte[] input = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		byte[] output2 = mac0.doFinal(input);
		Assertions.notHasEnsuredPredicate(output2);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest9() throws IllegalStateException, BadPaddingException, NoSuchPaddingException,
			IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		Certificate cert = null;
		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

		int outOffset = 0;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.doFinal(cipherText, outOffset);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest10() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {

		byte inp = 0;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		mac0.update(inp);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest11()
			throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

		byte inp = 0;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5", (Provider) null);
		mac0.init(key);
		mac0.update(inp);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest12() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException,
			InvalidAlgorithmParameterException {

		int outputLength = 0;

		HMACParameterSpec hMACParameterSpec0 = new HMACParameterSpec(outputLength);
		Assertions.hasEnsuredPredicate(hMACParameterSpec0);
		Assertions.mustBeInAcceptingState(hMACParameterSpec0);

		byte inp = 0;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key, hMACParameterSpec0);
		mac0.update(inp);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest13() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {

		byte[] pre_input = null;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		mac0.update(pre_input);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest14() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {

		int offset = 0;
		int len = 0;
		byte[] pre_input = null;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		mac0.update(pre_input, offset, len);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest15() throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {

		byte[] pre_input = null;
		Key key = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.init(key);
		mac0.update(pre_input);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest16() throws IllegalStateException, NoSuchAlgorithmException {

		byte inp = 0;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.update(inp);
		byte[] output1 = mac0.doFinal();
		Assertions.notHasEnsuredPredicate(output1);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest17() throws IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {

		byte inp = 0;

		Mac mac0 = Mac.getInstance("HmacMD5", (Provider) null);
		mac0.update(inp);
		byte[] output1 = mac0.doFinal();
		Assertions.notHasEnsuredPredicate(output1);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest18() throws IllegalStateException, NoSuchAlgorithmException {

		byte[] pre_input = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.update(pre_input);
		byte[] output1 = mac0.doFinal();
		Assertions.notHasEnsuredPredicate(output1);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest19() throws IllegalStateException, NoSuchAlgorithmException {

		int offset = 0;
		int len = 0;
		byte[] pre_input = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.update(pre_input, offset, len);
		byte[] output1 = mac0.doFinal();
		Assertions.notHasEnsuredPredicate(output1);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest20() throws IllegalStateException, NoSuchAlgorithmException {

		byte[] pre_input = null;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.update(pre_input);
		byte[] output1 = mac0.doFinal();
		Assertions.notHasEnsuredPredicate(output1);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest21() throws IllegalStateException, NoSuchAlgorithmException {

		byte[] input = null;
		byte inp = 0;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.update(inp);
		byte[] output2 = mac0.doFinal(input);
		Assertions.notHasEnsuredPredicate(output2);
		Assertions.mustNotBeInAcceptingState(mac0);

	}

	@Test
	public void macInvalidTest22() throws IllegalStateException, BadPaddingException, NoSuchPaddingException,
			IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException {

		Certificate cert = null;
		byte[] plainText = null;
		byte[] pre_plaintext = null;

		Cipher cipher0 = Cipher.getInstance("RSA");
		cipher0.init(1, cert);
		byte[] pre_ciphertext = cipher0.update(pre_plaintext);
		byte[] cipherText = cipher0.doFinal(plainText);
		Assertions.hasEnsuredPredicate(cipherText);
		Assertions.mustBeInAcceptingState(cipher0);

		int outOffset = 0;
		byte inp = 0;

		Mac mac0 = Mac.getInstance("HmacMD5");
		mac0.update(inp);
		mac0.doFinal(cipherText, outOffset);
		Assertions.notHasEnsuredPredicate(cipherText);
		Assertions.mustNotBeInAcceptingState(mac0);

	}
}