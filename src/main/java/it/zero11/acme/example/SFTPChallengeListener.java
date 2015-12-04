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
import java.util.Vector;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.x509.util.StreamParsingException;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.ChannelSftp.LsEntry;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;

public class SFTPChallengeListener implements AcmeChallengeListener {
	private final String host;
	private final int port;
	private final String username;
	private final String password;
	private final String webroot;
	
	public SFTPChallengeListener(String host, int port, String username, String password, String webroot) {
		this.host = host;
		this.port = port;
		this.username = username;
		this.password = password;
		this.webroot = webroot;
	}

	@Override
	public boolean challengeHTTP01(String domain, String token, String challengeURI, String challengeBody) {
		return createChallengeFiles(token, challengeBody);
	}

	private boolean createChallengeFiles(String token, String challengeBody) {
		boolean success = false;
		JSch jsch = new JSch();
		Session session = null;
		try {
			session = jsch.getSession(username, host, port);
			session.setPassword(password);
			java.util.Properties config = new java.util.Properties();
			config.put("StrictHostKeyChecking", "no");
			session.setConfig(config);
			session.connect();
			Channel channel = session.openChannel("sftp");
			channel.connect();
			ChannelSftp channelSftp = (ChannelSftp) channel;
			channelSftp.cd(webroot);
			
			try{
				channelSftp.mkdir(".well-known");
			}catch(Exception e){}
			channelSftp.cd(".well-known");
			
			try{
				channelSftp.mkdir("acme-challenge");
			}catch(Exception e){}
			channelSftp.cd("acme-challenge");
			
			channelSftp.put(new ByteArrayInputStream(challengeBody.getBytes()), token, ChannelSftp.OVERWRITE);
			
			channelSftp.disconnect();
			session.disconnect();
			
			success = true;
		} catch (SftpException e) {
			return false;
		} catch (JSchException e) {
			throw new AcmeException(e);
		} finally {
			if(session != null && session.isConnected()) {
				session.disconnect();
			}
		}

		return success;
	}

	@Override
	public void challengeCompleted(String domain) {
		deleteChallengeFiles();
	}

	private void deleteChallengeFiles() {
		JSch jsch = new JSch();
		Session session = null;
		try {
			session = jsch.getSession(username, host, port);
			session.setPassword(password);
			java.util.Properties config = new java.util.Properties();
			config.put("StrictHostKeyChecking", "no");
			session.setConfig(config);
			session.connect();
			Channel channel = session.openChannel("sftp");
			channel.connect();
			ChannelSftp channelSftp = (ChannelSftp) channel;
			channelSftp.cd(webroot);
			
			channelSftp.cd(".well-known");
			channelSftp.cd("acme-challenge");
			
			Vector<LsEntry> subFiles = channelSftp.ls(".");
			 
	        if (subFiles != null && subFiles.size() > 0) {
	            for (LsEntry aFile : subFiles) {
	                String currentFileName = aFile.getFilename();
	                if (currentFileName.equals(".") || currentFileName.equals("..")) {
	                    continue;
	                }else{
	                	channelSftp.rm(currentFileName);
	                }
	            }
	        }
	        channelSftp.cd("..");
			channelSftp.rmdir("acme-challenge");
			channelSftp.cd("..");
			channelSftp.rmdir(".well-known");
			
			channelSftp.disconnect();
			session.disconnect();
		} catch (SftpException e) {
			//throw new AcmeException(e);
		} catch (JSchException e) {
			//throw new AcmeException(e);
		} finally {
			if(session != null && session.isConnected()) {
				session.disconnect();
			}
		}
	}

	@Override
	public void challengeFailed(String domain) {
		deleteChallengeFiles();
	}
}
