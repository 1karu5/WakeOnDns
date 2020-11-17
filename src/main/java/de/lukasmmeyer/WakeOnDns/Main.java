package de.lukasmmeyer.WakeOnDns;

import org.json.JSONObject;
import org.json.JSONTokener;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    private static final int READ_TIMEOUT = 10; // [ms]
    private static final int SNAPLEN = 65536; // [bytes]

    private static PcapNetworkInterface getDevByIp(String ip) {
        try {
            List<PcapNetworkInterface> devs = Pcaps.findAllDevs();
            for (PcapNetworkInterface dev : devs) {
                List<InetAddress> ips = dev.getAddresses().stream().map(PcapAddress::getAddress).collect(Collectors.toList());
                if (ips.contains(InetAddress.getByName(ip))) {
                    return dev;
                }
            }
        } catch (PcapNativeException | UnknownHostException e) {
            LOG.error(e.getMessage(), e);
        }
        return null;
    }

    private static DnsPacket getDNSPacket(Packet p) {
        Packet payload = p;

        while (payload.getPayload() != null && !(payload instanceof DnsPacket)) {
            payload = payload.getPayload();
        }
        if (payload instanceof DnsPacket) {
            return (DnsPacket) payload;
        }
        return null;
    }

    private static byte[] buildMagicPaket(MacAddress dstAddr, byte[] password) {
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

    private static void wakeEmUp(String broadcastIP, MacAddress dstAddr, byte[] password) throws IOException {
        byte[] packetBytes = buildMagicPaket(dstAddr, password);
        InetAddress address = InetAddress.getByName(broadcastIP);
        DatagramPacket packet = new DatagramPacket(packetBytes, packetBytes.length, address, 9);
        DatagramSocket socket = new DatagramSocket();
        socket.send(packet);
        socket.close();
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException, InterruptedException, FileNotFoundException {

        if (args.length != 1) {
            LOG.error("Wrong arguments! Specify only config path!");
        }

        LOG.warn("Starting...read config");

        JSONObject config = new JSONObject(new JSONTokener(new FileInputStream(args[0])));
        String interfaceIP = config.getString("interfaceIP");
        String broadcastIP = config.getString("broadcastIP");

        JSONObject jsonWakeupMap = config.getJSONObject("wakeupMap");
        Map<String, byte[]> wakeupMap = new HashMap<>();

        for (String key : jsonWakeupMap.keySet()) {
            String mac = jsonWakeupMap.getString(key);
            byte[] value = new byte[6];
            int i = 0;

            for (String bytePart : mac.split(":")) {
                value[i++] = (byte) Integer.parseInt(bytePart, 16);
            }

            wakeupMap.put(key, value);
        }

        LOG.warn("interfaceIP: {} broadcastIP: {}", interfaceIP, broadcastIP);

        PcapNetworkInterface dev = getDevByIp(interfaceIP);

        if (dev == null) {
            LOG.error("NO INTERFACE FOUND!");
            return;
        }

        PcapHandle pcapHandle = dev.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        pcapHandle.setFilter("udp and port 53", BpfProgram.BpfCompileMode.OPTIMIZE);

        pcapHandle.loop(-1, (PacketListener) packet -> {
            DnsPacket dns = getDNSPacket(packet);
            if (dns != null && !dns.getHeader().isResponse()) {
                LOG.debug("Process package...");
                List<DnsQuestion> questions = dns.getHeader().getQuestions();
                for (DnsQuestion q : questions) {
                    String askedForName = q.getQName().getName();
                    LOG.debug("Asked for: {}", askedForName);
                    if (wakeupMap.containsKey(askedForName)) {
                        byte[] toMac = wakeupMap.get(askedForName);
                        LOG.warn("Found match, send WOL: {} {}", askedForName, toMac);
                        try {
                            wakeEmUp(broadcastIP, MacAddress.getByAddress(toMac), new byte[]{});
                        } catch (IOException e) {
                            LOG.error(e.getMessage(), e);
                        }
                    }
                }
                LOG.debug("Process done!");
            }
        });
    }
}
