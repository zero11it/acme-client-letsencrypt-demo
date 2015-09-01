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
import it.zero11.acme.storage.impl.DefaultCertificateStorage;

import java.io.IOException;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.x509.util.StreamParsingException;

public class LetsEncryptDemo {
	private static final String CA_STAGING_URL = "https://acme-staging.api.letsencrypt.org/acme";

	public static void main(String args[]) throws IOException, OperatorCreationException, InterruptedException, StreamParsingException{
		if (args.length != 5){
			System.out.println("Usage: java -jar acme-client-letsencrypt-demo.jar <domain> <ftpuser> <ftppassword> <ftprootfolder> <agreementURL>");
			System.out.println("The current Let's Encrypt Terms and Conditions you need to agree can be found here: https://letsencrypt.org/documents/LE-SA-v1.0-June-23-2015.pdf");
		}else{
			System.out.println("WARNING: this sample application is using the Let's Encrypt staging API. Certificated created with this application won't be trusted.");
			System.out.println("By using this application you agree to Let's Encrypt Terms and Conditions");
			System.out.println(args[4]);
			System.out.println("Press y if you agree to continue");
			int response = System.in.read();
			if (response == 'y' || response == 'Y'){
				Acme acme = new Acme(CA_STAGING_URL,
						new DefaultCertificateStorage(),
						new FTPChallengeListener(args[0], args[1], args[2], args[3]), true);

				acme.getCertificate(args[0], args[4], null);
			}
		}
	}
}
