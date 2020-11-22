package de.lukasmmeyer.WakeOnDns;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.pcap4j.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    private static List<NetworkInterfaceListener> listeners;

    public static void shutdownListeners() {
        LOG.info("Shutdown listeners...");
        for (NetworkInterfaceListener listener : listeners) {
            listener.interrupt();
        }
        waitForListeners(5000);
        LOG.info("All listeners stopped!");
    }

    public static void waitForListeners() {
        waitForListeners(0);
    }

    public static void waitForListeners(long timeout) {
        for (NetworkInterfaceListener listener : listeners) {
            try {
                listener.join(timeout);
            } catch (InterruptedException ignored) {
            }
        }
    }

    private static boolean isIP(String interfaceDescription) {
        try {
            if (interfaceDescription.isEmpty()) {
                return false;
            }
            String[] parts = interfaceDescription.split("\\.");
            if (parts.length != 4) {
                return false;
            }
            for (String s : parts) {
                int i = Integer.parseInt(s);
                if ((i < 0) || (i > 255)) {
                    return false;
                }
            }
            return !interfaceDescription.endsWith(".");
        } catch (NumberFormatException nfe) {
            return false;
        }
    }


    private static PcapNetworkInterface getDevByIp(List<PcapNetworkInterface> allDevices, String ip) throws UnknownHostException {
        for (PcapNetworkInterface dev : allDevices) {
            List<InetAddress> ips = dev.getAddresses().stream().map(PcapAddress::getAddress).collect(Collectors.toList());
            if (ips.contains(InetAddress.getByName(ip))) {
                return dev;
            }
        }
        return null;
    }

    private static PcapNetworkInterface getDevByName(List<PcapNetworkInterface> allDevices, String interfaceDescription) {
        for (PcapNetworkInterface dev : allDevices) {
            if (dev.getName().toLowerCase().equals(interfaceDescription.toLowerCase())) {
                return dev;
            }
        }
        return null;
    }


    public static void main(String[] args) throws PcapNativeException, FileNotFoundException, UnknownHostException {

        if (args.length != 1) {
            LOG.error("Wrong arguments! Specify only config path!");
        }

        LOG.info("Starting...read config...");

        JSONObject config = new JSONObject(new JSONTokener(new FileInputStream(args[0])));
        JSONArray jsonInterfaces = config.getJSONArray("interfaces");
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

        List<PcapNetworkInterface> allDevices = Pcaps.findAllDevs();

        List<PcapNetworkInterface> devices = new ArrayList<>(jsonInterfaces.length());
        for (Object i : jsonInterfaces) {
            if (!(i instanceof String)) {
                LOG.error("Bad config format in 'interfaces'. Needs to be string array!");
                System.exit(1);
            }
            String interfaceDescription = (String) i;
            PcapNetworkInterface device;
            if (isIP(interfaceDescription)) {
                device = getDevByIp(allDevices, interfaceDescription);
            } else {
                device = getDevByName(allDevices, interfaceDescription);
            }

            if (device != null) {
                LOG.info("Added '{}'", device.getName());
                devices.add(device);
            } else {
                LOG.error("No device found for '{}'", interfaceDescription);
            }
        }

        if (devices.isEmpty()) {
            LOG.error("No devices found!");
            System.exit(1);
        }

        LOG.info("Will send WOL pakets to: {}", broadcastIP);

        WakeEmUp waker = new WakeEmUp(broadcastIP, wakeupMap);

        Thread.UncaughtExceptionHandler uncaughtExceptionHandler = (th, ex) -> {
            LOG.error("Error in {}", th.getName());
            LOG.error(ex.getMessage(), ex);
            shutdownListeners();
        };

        listeners = new ArrayList<>(devices.size());
        for (PcapNetworkInterface dev : devices) {
            NetworkInterfaceListener listener = new NetworkInterfaceListener(dev, waker);
            listeners.add(listener);
            listener.setUncaughtExceptionHandler(uncaughtExceptionHandler);
            listener.start();
        }

        Runtime.getRuntime().addShutdownHook(new Thread(Main::shutdownListeners));

        waitForListeners();

        LOG.info("Finished");
    }
}
