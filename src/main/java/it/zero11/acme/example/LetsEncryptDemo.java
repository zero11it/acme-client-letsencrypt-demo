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

import it.zero11.acme.Acme;
import it.zero11.acme.AcmeChallengeListener;
import it.zero11.acme.storage.impl.DefaultCertificateStorage;

import java.io.IOException;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.x509.util.StreamParsingException;

public class LetsEncryptDemo {
	private static final String CA_STAGING_URL = "https://acme-staging.api.letsencrypt.org/acme";
	private static final String CA_PRODUCTION_URL = "https://acme-v01.api.letsencrypt.org/acme";
	private static final String AGREEMENT_URL = "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf";

	public static void main(String args[]) throws IOException, OperatorCreationException, InterruptedException, StreamParsingException{
		if (args.length != 7){
			System.out.println("Usage: java -jar acme-client-letsencrypt-demo.jar <domain> <protocol> <(s)ftpuser> <(s)ftppassword> <(s)ftprootfolder> <agreementURL> <email>");
			System.out.println("Currently supported protocols are sftp and ftp");
			System.out.println(String.format("The current Let's Encrypt Terms and Conditions you need to agree can be found here: %s", AGREEMENT_URL));
		}else if (!args[6].startsWith("mailto:")){
			System.out.println("WARNING: contact must start with mailto: ");
		}else{
			System.out.println("WARNING: this sample application is using the Let's Encrypt staging API. Certificated created with this application won't be trusted.");
			System.out.println("By using this application you agree to Let's Encrypt Terms and Conditions");
			System.out.println(args[5]);
			System.out.println("Press y if you agree to continue");
			int response = System.in.read();
			if (response == 'y' || response == 'Y'){
				String port = "22";
				if (args[0].contains(":")){
					port = args[0].split(":")[1];
					args[0] = args[0].split(":")[0];
				}

				String[] domains = args[0].split(",");
				AcmeChallengeListener challengeListener;
				switch (args[1]){
				case "ftp":
					challengeListener = new FTPChallengeListener(domains[0], args[2], args[3], args[4]);
					break;
				case "sftp":
					challengeListener = new SFTPChallengeListener(domains[0], Integer.parseInt(port), args[2], args[3], args[4]);
					break;
				default:
					System.out.println("Unknown protocol: " + args[1]);
					return;
				}

				Acme acme = new Acme(CA_STAGING_URL, new DefaultCertificateStorage(true), true, true);

				acme.getCertificate(domains, args[5], new String[]{args[6]}, challengeListener);
			}
		}
	}
}
