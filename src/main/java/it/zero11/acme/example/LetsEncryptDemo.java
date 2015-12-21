/**
 * Copyright (C) 2015 Zero11 S.r.l.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package it.zero11.acme.example;

import java.io.IOException;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.x509.util.StreamParsingException;

import it.zero11.acme.Acme;
import it.zero11.acme.AcmeChallengeListener;
import it.zero11.acme.storage.impl.DefaultCertificateStorage;

public class LetsEncryptDemo {
	private static final String CA_STAGING_URL = "https://acme-staging.api.letsencrypt.org/acme";
	private static final String CA_PRODUCTION_URL = "https://acme-v01.api.letsencrypt.org/acme";

	public static void main(final String args[]) throws IOException, OperatorCreationException, InterruptedException, StreamParsingException {
		if ((args.length != 7) && (args.length != 5)) {
			printUsage();
			return;
		}
		final String emailURL = (args.length == 7) ? args[6] : args[4];
		final String protocol = args[1];
		final String agreementURL = (args.length == 7) ? args[5] : args[3];
		final String webRoot = (args.length == 7) ? args[4] : args[2];

		if (!emailURL.startsWith("mailto:")) {
			System.out.println("WARNING: contact must start with mailto: ");
			return;
		}

		System.out.println("WARNING: this sample application is using the Let's Encrypt staging API. Certificated created with this application won't be trusted.");
		System.out.println("By using this application you agree to Let's Encrypt Terms and Conditions");
		System.out.println(agreementURL);
		System.out.println("Press y if you agree to continue");
		int response = System.in.read();
		if ((response == 'y') || (response == 'Y')) {
			String port = "22";
			if (args[0].contains(":")) {
				port = args[0].split(":")[1];
				args[0] = args[0].split(":")[0];
			}

			String[] domains = args[0].split(",");
			AcmeChallengeListener challengeListener;
			switch (protocol) {
			case "ftp":
				challengeListener = new FTPChallengeListener(domains[0], args[2], args[3], webRoot);
				break;
			case "sftp":
				challengeListener = new SFTPChallengeListener(domains[0], Integer.parseInt(port), args[2], args[3], webRoot);
				break;
			case "file":
				challengeListener = new LokalFileChallengeListener(webRoot);
				break;
			default:
				System.out.println("Unknown protocol: " + protocol);
				return;
			}

			Acme acme = new Acme(CA_STAGING_URL, new DefaultCertificateStorage(true), true, true);

			acme.getCertificate(domains, agreementURL, new String[] { emailURL }, challengeListener);

		}
	}

	/**
	 *
	 */
	private static void printUsage() {
		System.out.println("Usage: java -jar acme-client-letsencrypt-demo.jar <domain> <protocol> <(s)ftpuser> <(s)ftppassword> <(s)ftprootfolder> <agreementURL> <email>");
		System.out.println("Currently supported protocols are sftp and ftp");
		System.out.println(" or");
		System.out.println("       java -jar acme-client-letsencrypt-demo.jar <domain> file <webrootfolder> <agreementURL> <email>");
		System.out.println("The current Let's Encrypt Terms and Conditions you need to agree can be found here: https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf");
	}
}
