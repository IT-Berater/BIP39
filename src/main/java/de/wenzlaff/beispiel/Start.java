package de.wenzlaff.beispiel;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import io.github.novacrypto.bip39.MnemonicGenerator;
import io.github.novacrypto.bip39.MnemonicValidator;
import io.github.novacrypto.bip39.Words;
import io.github.novacrypto.bip39.Validation.InvalidChecksumException;
import io.github.novacrypto.bip39.Validation.InvalidWordCountException;
import io.github.novacrypto.bip39.Validation.UnexpectedWhiteSpaceException;
import io.github.novacrypto.bip39.Validation.WordNotFoundException;
import io.github.novacrypto.bip39.wordlists.English;

/**
 * Ausgabe der 24 BIP39 Wörter in Englisch und der im System verwendeten
 * Security Provider.
 * 
 * @author Thomas Wenzlaff
 */
public class Start {

	public static void main(String[] args) throws Exception {

		getSecurityProviders();

		String wortliste = get24Wortliste();

		System.out.println("24 BIP39 Wörter in englisch:");
		System.out.println(wortliste);

	}

	private static String get24Wortliste() throws InvalidChecksumException, InvalidWordCountException, WordNotFoundException, UnexpectedWhiteSpaceException {

		SecureRandom secureRan = new SecureRandom();
		System.out.println("Verwende Provider: " + secureRan.getProvider());

		byte[] entropy = new byte[Words.TWENTY_FOUR.byteLength()];

		secureRan.nextBytes(entropy);

		StringBuilder sb = new StringBuilder();
		new MnemonicGenerator(English.INSTANCE).createMnemonic(entropy, sb::append);

		MnemonicValidator.ofWordList(English.INSTANCE).validate(sb.toString());

		return sb.toString();
	}

	private static Provider[] getSecurityProviders() {
		System.out.println("Alle im System bekannten Security Provider:");
		Provider[] provider = Security.getProviders();
		for (int i = 0; i < provider.length; i++) {
			System.out.println(provider[i]);
		}
		return provider;
	}
}
