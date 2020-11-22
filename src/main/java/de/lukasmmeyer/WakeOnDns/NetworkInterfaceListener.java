package de.lukasmmeyer.WakeOnDns;

import org.pcap4j.core.*;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.Packet;
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

    private DnsPacket getDNSPacket(Packet p) {
        Packet payload = p;

        while (payload.getPayload() != null && !(payload instanceof DnsPacket)) {
            payload = payload.getPayload();
        }
        if (payload instanceof DnsPacket) {
            return (DnsPacket) payload;
        }
        return null;
    }

    @Override
    public void run() {
        LOG.info("Listening on {}", device.getName());
        try {
            pcapHandle = device.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
            pcapHandle.setFilter("udp and port 53", BpfProgram.BpfCompileMode.OPTIMIZE);

            pcapHandle.loop(-1, (PacketListener) packet -> {
                DnsPacket dns = getDNSPacket(packet);
                if (dns != null && !dns.getHeader().isResponse()) {
                    LOG.debug("Process package...");
                    List<DnsQuestion> questions = dns.getHeader().getQuestions();
                    for (DnsQuestion q : questions) {
                        String askedForName = q.getQName().getName();
                        this.waker.wakeUpIfNecessary(askedForName);
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
