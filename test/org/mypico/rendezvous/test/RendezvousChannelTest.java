package org.mypico.rendezvous.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

import org.junit.Before;
import org.junit.Test;
import org.mypico.rendezvous.RendezvousChannel;
import org.mypico.rendezvous.RendezvousClient;

public class RendezvousChannelTest {
	private static final Charset UTF8 = Charset.forName("UTF-8");
	
	private RendezvousChannel channel;

	@Before
	public void setUp() throws Exception {
		final RendezvousClient client = new RendezvousClient("http://rendezvous.mypico.org");
		channel = client.newChannel();
	}

	@Test
	public void writeReadHelloWorld() throws IOException {
		final BufferedOutputStream os = new BufferedOutputStream(channel.getOutputStream());
		final InputStream is = channel.getInputStream();
		
		final String helloWorld = "hello world";
		final byte[] helloWorldBytes = helloWorld.getBytes(UTF8);
		
		// Write in another thread
		new Thread(new Runnable() {
			public void run() {
				try {
					os.write(helloWorldBytes);
					os.flush();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}).start();
		
		// Read
		final byte[] bytesRead = new byte[helloWorldBytes.length];
		is.read(bytesRead, 0, bytesRead.length);
		final String stringRead = new String(bytesRead, UTF8);
		
		// Test
		assertArrayEquals(helloWorldBytes, bytesRead);
		assertEquals(helloWorld, stringRead);
	}
	
	@Test
	public void echoHelloWorld() throws Exception {
		final DataOutputStream os = new DataOutputStream(new BufferedOutputStream(channel.getOutputStream()));
		final DataInputStream is = new DataInputStream(channel.getInputStream());
		
		final RendezvousChannel peer = new RendezvousChannel(channel.getUrl());
		final DataOutputStream peerOs = new DataOutputStream(new BufferedOutputStream(peer.getOutputStream()));
		final DataInputStream peerIs = new DataInputStream(peer.getInputStream());
		
		// Peer echoes anything back to the rendezvous point in another thread
		new Thread(new Runnable() {
			public void run() {
				try {
					while(true) {
						byte[] peerBuffer = new byte[1024];
						final int length = peerIs.readInt();
						peerIs.read(peerBuffer, 0, length);
						String stringRead = new String(peerBuffer, 0, length);
						if (stringRead.equals("exit")) {
							break;
						}
						peerOs.write(peerBuffer, 0, length);
						peerOs.flush();
					}
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}).start();
		
		// See if something is echoed correctly...
		final String helloWorld = "hello world";
		final byte[] helloWorldBytes = helloWorld.getBytes();
		final int length = helloWorldBytes.length;
		
		// Write
		os.writeInt(length);
		os.write(helloWorldBytes, 0, length);
		os.flush();
		
		// Read
		final byte[] bytesRead = new byte[length];
		is.read(bytesRead, 0, length);
		final String stringRead = new String(bytesRead);
		
		// Test
		assertArrayEquals(helloWorldBytes, bytesRead);
		assertEquals(helloWorld, stringRead);

		// Finish thread
		final String exit = "exit";
		final byte[] exitBytes = exit.getBytes();
		os.writeInt(exitBytes.length);
		os.write(exitBytes, 0, exitBytes.length);
		os.flush();
	}
	
	@Test
	public void rendezvousTimesOut() throws Exception {
		final RendezvousChannel c = new RendezvousChannel(channel.getUrl(), 1000);
		
		Thread readThread = new Thread(new Runnable() {
			public void run() {
				final DataInputStream is = new DataInputStream(c.getInputStream());
				try {
					is.readInt();
					assertEquals(true, false); // readInt should throw exception			
				} catch (java.net.SocketTimeoutException e) {
					// Times out... That is excepted
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
			}
		});
		
		readThread.start();
		
		Thread.sleep(2000);

		if (readThread.isAlive()) {
			c.close();
			assertEquals(true, false); // Thread should have finished
		}
		
	}
}
