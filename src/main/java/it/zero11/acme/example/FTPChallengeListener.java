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

import it.zero11.acme.AcmeChallengeListener;
import it.zero11.acme.AcmeException;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPFile;
import org.apache.commons.net.ftp.FTPReply;

public class FTPChallengeListener implements AcmeChallengeListener {
	private final String host;
	private final String username;
	private final String password;
	private final String webroot;
	
	public FTPChallengeListener(String host, String username, String password, String webroot) {
		this.host = host;
		this.username = username;
		this.password = password;
		this.webroot = webroot;
	}

	@Override
	public boolean challengeSimpleHTTP(String domain, String token, String challengeURI, String challengeBody) {
		return createChallengeFiles(token, challengeBody);
	}

	private boolean createChallengeFiles(String token, String challengeBody) {
		boolean success = false;
		FTPClient ftp = new FTPClient();
		try {
			ftp.connect(host);
			if(!FTPReply.isPositiveCompletion(ftp.getReplyCode())) {
				ftp.disconnect();
				return false;
			}

			ftp.login(username, password);
			ftp.changeWorkingDirectory(webroot);
			ftp.makeDirectory(".well-known");
			ftp.changeWorkingDirectory(".well-known");
			ftp.makeDirectory("acme-challenge");
			ftp.changeWorkingDirectory("acme-challenge");
			ftp.enterLocalPassiveMode();
			ftp.setFileType(FTPClient.BINARY_FILE_TYPE, FTPClient.BINARY_FILE_TYPE);
	        ftp.setFileTransferMode(FTPClient.BINARY_FILE_TYPE);
			success = ftp.storeFile(token, new ByteArrayInputStream(challengeBody.getBytes()));
			if (!success)
				System.err.println("FTP error uploading file: " + ftp.getReplyCode()  + ": " + ftp.getReplyString());
			ftp.logout();
		} catch(IOException e) {
			throw new AcmeException(e);
		} finally {
			if(ftp.isConnected()) {
				try {
					ftp.disconnect();
				} catch(IOException ioe) {
				}
			}
		}

		return success;
	}

	@Override
	public void challengeCompleted(String domain) {
		deleteChallengeFiles();
	}

	private void deleteChallengeFiles() {
		FTPClient ftp = new FTPClient();
		try {
			ftp.connect(host);
			if(!FTPReply.isPositiveCompletion(ftp.getReplyCode())) {
				ftp.disconnect();
				return;
			}

			ftp.login(username, password);
			ftp.changeWorkingDirectory(webroot);
			ftp.changeWorkingDirectory(".well-known");
			ftp.changeWorkingDirectory("acme-challenge");
			
			FTPFile[] subFiles = ftp.listFiles();
			 
	        if (subFiles != null && subFiles.length > 0) {
	            for (FTPFile aFile : subFiles) {
	                String currentFileName = aFile.getName();
	                if (currentFileName.equals(".") || currentFileName.equals("..")) {
	                    continue;
	                }else{
	                	ftp.deleteFile(currentFileName);
	                }
	            }
	        }
			ftp.changeToParentDirectory();
			ftp.removeDirectory("acme-challenge");
			ftp.changeToParentDirectory();
			ftp.removeDirectory(".well-known");
			ftp.logout();
		} catch(IOException e) {
			throw new AcmeException(e);
		} finally {
			if(ftp.isConnected()) {
				try {
					ftp.disconnect();
				} catch(IOException ioe) {
				}
			}
		}
	}

	@Override
	public void challengeFailed(String domain) {
		deleteChallengeFiles();
	}
}
