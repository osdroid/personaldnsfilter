package dnsfilter;

/*
 PersonalDNSFilter 1.5
 Copyright (C) 2017 Ingo Zenz

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

 Find the latest version at http://www.zenz-solutions.de/personaldnsfilter
 Contact:i.z@gmx.net
 */


import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;

import util.ExecutionEnvironment;
import util.GroupedLogger;
import util.Logger;
import util.LoggerInterface;
import util.SuppressRepeatingsLogger;

public class DNSFilterProxy implements Runnable {

	DatagramSocket receiver;
	boolean stopped = false;
	int port = 53;

	public DNSFilterProxy(int port) {
		this.port = port;
	}

	private static void initDNS(DNSFilterManager dnsFilterMgr) {
		try {

			boolean detect = Boolean.parseBoolean(dnsFilterMgr.getConfig().getProperty("detectDNS", "true"));
			if (detect) {
				Logger.getLogger().logLine("DNS detection not supported for this device");
				Logger.getLogger().message("DNS detection not supported - Using fallback!");
			}

			int timeout = Integer.parseInt(dnsFilterMgr.getConfig().getProperty("dnsRequestTimeout", "15000"));
			String specList = dnsFilterMgr.getConfig().getProperty("fallbackDNS", "");
			DNSServer[] dnsServers = DNSServer.getInstance().createDNSServers(specList, timeout, false);
			DNSCommunicator.getInstance().setDNSServers(dnsServers);
        } catch (IOException e) {
            Logger.getLogger().logLine("!!!DNS server initialization failed!!!");
            Logger.getLogger().logLine(e.toString());
            Logger.getLogger().message(e.getMessage());
        } catch (Exception e) {
            Logger.getLogger().logException(e);
        }
	}

	private static InetAddress openVPN4pDNSf_Adr;

	{
		try {
			openVPN4pDNSf_Adr = InetAddress.getByName("10.10.10.10");
		} catch (UnknownHostException e) {
			Logger.getLogger().logException(e);
		}
	}

	public static boolean isAlocalAddress(InetAddress addr) throws IOException {

		if (addr.equals(openVPN4pDNSf_Adr)  || addr.isLoopbackAddress() || addr.isAnyLocalAddress())
			return true;

		return NetworkInterface.getByInetAddress(addr) != null;
	}

	@Override
	public void run() {
		int max_resolvers;
		boolean onlyLocal;
		boolean androidRootMode;
		try {
			max_resolvers  = Integer.parseInt(DNSFilterManager.getInstance().getConfig().getProperty("maxResolverCount", "100"));
			onlyLocal = Boolean.parseBoolean(DNSFilterManager.getInstance().getConfig().getProperty("dnsProxyOnlyLocalRequests", "true"));
			androidRootMode = Boolean.parseBoolean(DNSFilterManager.getInstance().getConfig().getProperty("rootModeOnAndroid", "false"));
		} catch (Exception e) {
			Logger.getLogger().logLine("Exception:Cannot get configuration!");
			Logger.getLogger().logException(e);
			return;
		}
		try {
			if (onlyLocal && (ExecutionEnvironment.getEnvironment().getEnvironmentID() == 0 || androidRootMode))
				//currently only possible for non Android - see below!
				receiver = new DatagramSocket(port, InetAddress.getByName("127.0.0.1"));
			else
				receiver = new DatagramSocket(port);

			ExecutionEnvironment.getEnvironment().protectSocket(receiver, 1);

		} catch (IOException eio) {
			Logger.getLogger().logLine("Exception:Cannot open DNS port " + port + "!" + eio.getMessage());
			return;
		}
		Logger.getLogger().logLine("DNSFilterProxy running on port " + port + "!");

		while (!stopped) {
			try {
				byte[] data = new byte[DNSServer.getBufSize()];
				DatagramPacket request = new DatagramPacket(data, 0, DNSServer.getBufSize());
				receiver.receive(request);

				boolean permitted = true;
				// This is temporary solution on Android as here we can not open the localhost socket only
				// due to interoperability with openVPN for pDNSf.
				// Will work on better solution for next release
				if (onlyLocal && ExecutionEnvironment.getEnvironment().getEnvironmentID() == 1 && !androidRootMode)
					permitted = isAlocalAddress(request.getAddress());

				if (!permitted)
					Logger.getLogger().logLine(request.getAddress()+" not permitted! Only local access!");

				if (DNSResolver.getResolverCount()>max_resolvers) {
					Logger.getLogger().message("Max resolver count reached: "+max_resolvers);
				}
				else if (permitted)
					new Thread(new DNSResolver(request, receiver)).start();

			} catch (IOException e) {
				if (!stopped)
					Logger.getLogger().logLine("Exception:" + e.getMessage());
			}
		}
		Logger.getLogger().logLine("DNSFilterProxy stopped!");
	}


	public synchronized void stop() {
		stopped = true;
		if (receiver == null)
			return;
		receiver.close();
	}


}
