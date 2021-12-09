package de.lukasmmeyer.WakeOnDns;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class NetworkInterfaceListener extends Thread {

    private static final Logger LOG = LoggerFactory.getLogger(NetworkInterfaceListener.class);

    private static final int READ_TIMEOUT = 10; // [ms]
    private static final int SNAPLEN = 65536; // [bytes]

    private final PcapNetworkInterface device;
    private final WakeEmUp waker;
    private PcapHandle pcapHandle;

    public NetworkInterfaceListener(PcapNetworkInterface dev, WakeEmUp waker) {
        this.device = dev;
        this.waker = waker;
        this.setName("NetworkInterfaceListener " + dev.getName());
    }

    @Override
    public void run() {
        LOG.info("Listening on {}", device.getName());
        try {
            pcapHandle = device.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
            pcapHandle.setFilter("udp and port 53", BpfProgram.BpfCompileMode.OPTIMIZE);

            pcapHandle.loop(-1, (PacketListener) packet -> {
                IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
                DnsPacket dnsPacket = packet.get(DnsPacket.class);
                String srcAddress = "unknown";

                if(ipV4Packet != null){
                    srcAddress = ipV4Packet.getHeader().getSrcAddr().toString();
                } else if(ipV6Packet != null){
                    srcAddress = ipV6Packet.getHeader().getSrcAddr().toString();
                }
                if (dnsPacket != null && !dnsPacket.getHeader().isResponse()) {
                    LOG.debug("Process package...");

                    List<DnsQuestion> questions = dnsPacket.getHeader().getQuestions();
                    for (DnsQuestion q : questions) {
                        String askedForName = q.getQName().getName();
                        this.waker.wakeUpIfNecessary(askedForName, srcAddress);
                    }

                    LOG.debug("Process done!");
                }
            });
        } catch (PcapNativeException | NotOpenException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            LOG.info("Loop is interrupted!");
        } finally {
            if (pcapHandle != null) {
                pcapHandle.close();
            }
        }
    }

    @Override
    public void interrupt() {
        if (pcapHandle != null) {
            try {
                pcapHandle.breakLoop();
            } catch (NotOpenException e) {
                LOG.error(e.getMessage(), e);
            }
        }
        super.interrupt();
    }
}
