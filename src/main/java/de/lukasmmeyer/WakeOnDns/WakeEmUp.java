package de.lukasmmeyer.WakeOnDns;

import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Map;

public class WakeEmUp {

    private static final Logger LOG = LoggerFactory.getLogger(WakeEmUp.class);

    private final Map<String, byte[]> wakeupMap;
    private final String broadcastIP;

    public WakeEmUp(String broadcastIP, Map<String, byte[]> wakeupMap) {
        this.broadcastIP = broadcastIP;
        this.wakeupMap = wakeupMap;
    }

    public synchronized void wakeUpIfNecessary(String dnsName) {
        LOG.debug("Asked for: {}", dnsName);
        if (wakeupMap.containsKey(dnsName)) {
            byte[] toMac = wakeupMap.get(dnsName);
            LOG.info("Found match, send WOL: {} {}", dnsName, macToString(toMac));
            try {
                wakeEmUp(broadcastIP, MacAddress.getByAddress(toMac), new byte[]{});
            } catch (IOException e) {
                LOG.error(e.getMessage(), e);
            }
        }
    }

    private void wakeEmUp(String broadcastIP, MacAddress dstAddr, byte[] password) throws IOException {
        byte[] packetBytes = buildMagicPaket(dstAddr, password);
        InetAddress address = InetAddress.getByName(broadcastIP);
        DatagramPacket packet = new DatagramPacket(packetBytes, packetBytes.length, address, 9);
        DatagramSocket socket = new DatagramSocket();
        socket.send(packet);
        socket.close();
    }

    private byte[] buildMagicPaket(MacAddress dstAddr, byte[] password) {
        byte[] macBytes = dstAddr.getAddress();
        byte[] rawData = new byte[6 + (16 * macBytes.length) + password.length];

        for (int i = 0; i < 6; i++) {
            rawData[i] = (byte) 0xff;
        }
        for (int i = 6; i <= (16 * macBytes.length); i += macBytes.length) {
            System.arraycopy(macBytes, 0, rawData, i, macBytes.length);
        }
        System.arraycopy(password, 0, rawData, (16 * macBytes.length), password.length);

        return rawData;
    }

    private String macToString(byte[] mac) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            if (i != 0) {
                stringBuilder.append(":");
            }
            stringBuilder.append(String.format("%02X", mac[i]));
        }
        return stringBuilder.toString();
    }

}
