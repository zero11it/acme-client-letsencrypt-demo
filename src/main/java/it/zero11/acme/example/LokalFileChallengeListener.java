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

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import java.io.IOException;

import it.zero11.acme.AcmeChallengeListener;
import it.zero11.acme.AcmeException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class LokalFileChallengeListener implements AcmeChallengeListener {
	private final String webroot;
	private final Set<Path> createdFiles = new HashSet<>();

	public LokalFileChallengeListener(final String webroot) {
		this.webroot = webroot;
	}

	@Override
	public boolean challengeHTTP01(final String domain, final String token, final String challengeURI, final String challengeBody) {
		return createChallengeFiles(token, challengeBody);
	}

	private boolean createChallengeFiles(final String token, final String challengeBody) {
		try {
			Path path = Paths.get(webroot, ".well-known", "acme-challenge", token);
			Files.createDirectories(path.getParent());
			Files.write(path, challengeBody.getBytes());
			createdFiles.add(path);
			return true;
		} catch (IOException e) {
			throw new AcmeException(e);
		}
	}

	@Override
	public void challengeCompleted(final String domain) {
		deleteChallengeFiles();
	}

	private void deleteChallengeFiles() {
		for (Iterator<Path> i = createdFiles.iterator(); i.hasNext(); i.remove()) {
			try {
				Files.deleteIfExists(i.next());
			} catch (IOException e) {
				throw new AcmeException(e);
			}
		}
	}

	@Override
	public void challengeFailed(final String domain) {
		deleteChallengeFiles();
	}
}
