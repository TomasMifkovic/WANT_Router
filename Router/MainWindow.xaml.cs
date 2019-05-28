using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Linq;
using System.Text;
using System.Timers;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using SharpPcap;
using SharpPcap.WinPcap;
using PacketDotNet;
using PacketDotNet.LSA;

namespace Router
{
    /*
     * ================================================================
     *              OSPF SPF VERTEX
     * ================================================================
     */

    public class Vertex
    {
        public LSA lsa;
        public IPAddress vertex_id;
        public Vertex reverse;
        public int distance;

        public Vertex(IPAddress id, LSA l, int cost, Vertex vertex)
        {
            this.distance = cost;
            this.lsa = l;
            this.vertex_id = id;
            this.reverse = vertex;
        }
    }

    /*
     * ================================================================
     *              OSPF DATABASE ITEM
     * ================================================================
     */

    public class DatabaseRecord
    {
        public LSA lsa;
        public int learned;

        public DatabaseRecord(LSA lsa)
        {
            this.lsa = lsa;
            this.learned = 0;
        }
    }

    /*
     * ================================================================
     *              OSPF PROCES
     * ================================================================
     */

    public class Proces
    {
        public IPAddress AreaID = IPAddress.Parse("0.0.0.0");
        public ushort hello_interval = 10;
        public ushort dead_interval = 40;
        public byte priority = 1;
        public List<IPAddress> DRs = new List<IPAddress>();
        public List<IPAddress> BDRs = new List<IPAddress>();

        public Proces()
        {
            DRs.Add(IPAddress.Parse("0.0.0.0"));
            DRs.Add(IPAddress.Parse("0.0.0.0"));
            BDRs.Add(IPAddress.Parse("0.0.0.0"));
            BDRs.Add(IPAddress.Parse("0.0.0.0"));
        }
    }

    /*
     * ================================================================
     *              OSPF SUSED
     * ================================================================
     */

    public class Neighbor
    {
        public IPAddress neighbor_id, ip_add, dr, bdr;
        public Port output;
        public uint priority, dead_time;
        public ushort state;
        public char typ;
        public bool master;
        public uint dd_seq;
        public OSPFv2DDPacket last_r, last_s = null;
        public List<LSA> retransmission_list, summary_list, request_list;
        public Mutex mutex;
        
        public Neighbor(IPAddress neighbor, IPAddress ip, uint pr, uint dead, ushort stav, Port port, IPAddress designated, IPAddress backup, bool ms, uint seq)
        {
            neighbor_id = neighbor;
            ip_add = ip;
            output = port;
            priority = pr;
            dead_time = dead;
            state = stav;
            dr = designated;
            bdr = backup;
            typ = 'O';
            dd_seq = seq;
            master = ms;
            retransmission_list = new List<LSA>();
            summary_list = new List<LSA>();
            request_list = new List<LSA>();
            mutex = new Mutex();
        }
        
        public String GetState(ushort state)
        {
            switch (state)
            {
                case 1: return "Init";
                case 2: return "2way";
                case 3: return "ExStart";
                case 4: return "Exchange";
                case 5: return "Loading";
                case 6: return "Full";
                default: return "Down";
            }
        }
        public String GetTyp(char typ)
        {
            switch (typ)
            {
                case 'D': return "DR";
                case 'B': return "BDR";
                default: return "OTHER";
            }
        }
        public String Vypis() => neighbor_id + "\t" + priority + "\t" + GetState(state) + "/" + GetTyp(typ) + "\t" + dead_time + "\t" + ip_add + "\t" + output.port.Description;

        public bool IsInstanceInRetransList(LSA lsa)
        {
            bool result = false;
            this.mutex.WaitOne();
            foreach(LSA l in retransmission_list)
            {
                if (l.LSType == lsa.LSType && l.LinkStateID.Equals(lsa.LinkStateID) && l.AdvertisingRouter.Equals(lsa.AdvertisingRouter))
                {
                    result = true;
                    break;
                }
            }
            this.mutex.ReleaseMutex();
            return result;
        }
        public LSA IsInstanceInRequestList(LSA lsa)
        {
            LSA result = null;
            mutex.WaitOne();
            foreach(LSA l in request_list)
            {
                if (l.LSType == lsa.LSType && l.LinkStateID.Equals(lsa.LinkStateID) && l.AdvertisingRouter.Equals(lsa.AdvertisingRouter))
                {
                    result = l;
                    break;
                }
            }
            mutex.ReleaseMutex();
            return result;
        }
        public void AddToRequestList(LSA lsa)
        {
            mutex.WaitOne();
            request_list.Add(lsa);
            mutex.ReleaseMutex();
        }
        public void AddToRetransList(LSA lsa)
        {
            mutex.WaitOne();
            retransmission_list.Add(lsa);
            mutex.ReleaseMutex();
        }
        public List<LSA> GetRequestList()
        {
            List<LSA> ret = null;
            mutex.WaitOne();
            ret = request_list;
            mutex.ReleaseMutex();
            return ret;
        }
        public void RemoveRetransLSA(LSA lsa)
        {
            LSA delete = null;
            mutex.WaitOne();
            foreach (LSA l in retransmission_list)
            {
                if (l.LSType == lsa.LSType && l.AdvertisingRouter.Equals(lsa.AdvertisingRouter) && l.LinkStateID.Equals(lsa.LinkStateID))
                {
                    delete = l;
                    break;
                }
            }
            if (delete != null) retransmission_list.Remove(delete);
            mutex.ReleaseMutex();
        }
        public void RemoveRequestLSA(LSA lsa)
        {
            mutex.WaitOne();
            request_list.Remove(lsa);
            mutex.ReleaseMutex();
        }
    }

    /*
     * ================================================================
     *              ZAZNAM V SMEROVACEJ TABULKE
     * ================================================================
     */

    public class RT_zaznam
    {
        public IPAddress ip_add, next_hop, maska;
        public int cidr_mask, metric;
        public Port output;
        public char type;

        public RT_zaznam(IPAddress network, IPAddress mask, IPAddress nexthop, Port port, char typ)
        {
            ip_add = network;
            maska = mask;
            cidr_mask = MaskToCIDR(mask);
            next_hop = nexthop;
            output = port;
            type = typ;
            if (typ == 'C') metric = 0;
            else if (typ == 'S') metric = 1;
            else if (typ == 'O') metric = 110;
            else if (typ == 'R') metric = 120;
        }
        public String Vypis()
        {
            if (output == null)
                return type + "\t" + ip_add + "/" + cidr_mask + "\t[" + metric +  "]\t" + "   via   " + next_hop;
            else if (next_hop == null)
                return type + "\t" + ip_add + "/" + cidr_mask + "\t[" + metric + "]\t" + "   via   " + output.port.Description;
            else return type + "\t" + ip_add + "/" + cidr_mask + "\t[" + metric + "]\t" + "   via   " + next_hop + "  -  " + output.port.Description;
        }
        public void SetCIDR(IPAddress mask) => cidr_mask = MaskToCIDR(mask);
        public int MaskToCIDR(IPAddress ip) => Convert
                   .ToString(BitConverter.ToInt32(ip.GetAddressBytes(), 0), 2)
                   .ToCharArray()
                   .Count(x => x == '1');
    }

    /*
     * ================================================================
     *              ZAZNAM V ARP TABULKE
     * ================================================================
     */

    public class ARP_zaznam
    {
        public IPAddress ip_add;
        public PhysicalAddress mac_add;
        public int timer;

        public ARP_zaznam(IPAddress IP, PhysicalAddress MAC, int time)
        {
            ip_add = IP;
            mac_add = MAC;
            timer = time;
        }
        public ARP_zaznam(String IP, String MAC, int time)
        {
            ip_add = IPAddress.Parse(IP);
            mac_add = PhysicalAddress.Parse(MAC);
            timer = time;
        }

        private String MACToString(String st) => "" + st[0] + st[1] + "-" + st[2] + st[3] + "-" + st[4] + st[5] + "-" + st[6] + st[7] + "-" + st[8] + st[9] + "-" + st[10] + st[11];
        public String Vypis() => ip_add + "\t" + MACToString(mac_add.ToString()) + "\t" + timer;
    }

    /*
     * ================================================================
     *              PORT
     * ================================================================
     */

    public class Port
    {
        public WinPcapDevice port = null;
        public IPAddress ip_add = null, maska = null;
        public bool ospf = false;
        public RouterLink router_link = null;
        public bool need_calculation = true;
        public int cost = 1;

        public Port(WinPcapDevice rozhranie) => port = rozhranie;
        public void SetIP(String ip) => ip_add = IPAddress.Parse(ip);
        public void SetMask(String mask) => maska = IPAddress.Parse(mask);
        public void SetRouterLink(IPAddress dr, ushort metric)
        {
            router_link = new RouterLink
            {
                LinkID = dr,
                LinkData = ip_add,
                Metric = metric
            };
        }
    }

    /*
     * ================================================================
     *              SMEROVAC
     * ================================================================
     */

    public class Smerovac
    {
        public IPAddress routerID;
        public Proces ospf;
        public List<Port> ports;
        public List<Neighbor> neighbors;
        public List<RT_zaznam> smerovacia_tabulka;
        public List<ARP_zaznam> arp_tabulka;
        public Mutex mut_arp, mut_rt, mut_sused, mut_database, mut_spf;
        public int arp_timer;
        public bool manualne_RID, neighbors_changed, lsa_changed;
        public List<DatabaseRecord> my_database;
        public RouterLSA my_lsa = null;
        public List<NetworkLSA> my_network_lsa = null;
        public List<RouterLink> links;

        public Smerovac(WinPcapDevice rozhranie1, WinPcapDevice rozhranie2)
        {
            mut_spf = new Mutex();
            ports = new List<Port>
            {
                new Port(rozhranie1),
                new Port(rozhranie2)
            };

            manualne_RID = false;
            neighbors = new List<Neighbor>();
            arp_tabulka = new List<ARP_zaznam>();
            smerovacia_tabulka = new List<RT_zaznam>();
            my_database = new List<DatabaseRecord>();
            mut_arp = new Mutex();
            mut_rt = new Mutex();
            mut_database = new Mutex();
            mut_sused = new Mutex();
            ospf = new Proces();
            links = new List<RouterLink>();
            my_network_lsa = new List<NetworkLSA>();
            arp_timer = 60;
        }
        
        public IPAddress GreaterIP(IPAddress ip1, IPAddress ip2) => IPAddressToLongBackwards(ip1) > IPAddressToLongBackwards(ip2) ? ip1 : ip2;

        static private uint IPAddressToLongBackwards(IPAddress IPAddr)
        {
            byte[] byteIP = IPAddr.GetAddressBytes();
            uint ip = (uint)byteIP[0] << 24;
            ip += (uint)byteIP[1] << 16;
            ip += (uint)byteIP[2] << 8;
            ip += (uint)byteIP[3];
            return ip;
        }

        public String VyberRID()
        {
            if (ports[0].ip_add == null)
            {
                routerID = ports[1].ip_add;
                return routerID.ToString();
            } else if (ports[1].ip_add == null)
            {
                routerID = ports[0].ip_add;
                return routerID.ToString();
            } else
            {
                return GreaterIP(ports[0].ip_add, ports[1].ip_add).ToString();
            }
        }

        public Port GetPortAt(int i) => ports.ElementAt(i);

        public void SetRouterID(String router_id) => routerID = IPAddress.Parse(router_id);

        public ushort ComputeChecksum(byte[] header, int start, int length)
        {
            ushort word16;
            long sum = 0;
            for (int i = start; i < (length + start); i += 2)
            {
                word16 = (ushort)(((header[i] << 8) & 0xFF00) + (header[i + 1] & 0xFF));
                sum += (long)word16;
            }

            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            sum = ~sum;

            return (ushort)sum;
        }

        public DatabaseRecord GetInstanceOfLSA(LSA lsa)
        {
            mut_database.WaitOne();
            foreach (DatabaseRecord l in my_database)
            {
                if (lsa.LSType == l.lsa.LSType && lsa.AdvertisingRouter.Equals(l.lsa.AdvertisingRouter) && lsa.LinkStateID.Equals(l.lsa.LinkStateID))
                {
                    mut_database.ReleaseMutex();
                    return l;
                }
            }
            mut_database.ReleaseMutex();

            return null;
        }

        public LSA GetRequestedLSA(LinkStateRequest lsa)
        {
            foreach (DatabaseRecord l in my_database)
            {
                if (lsa.LSType == l.lsa.LSType && lsa.AdvertisingRouter.Equals(l.lsa.AdvertisingRouter) && lsa.LinkStateID.Equals(l.lsa.LinkStateID))
                {
                    return l.lsa;
                }
            }
            return null;
        }

        public int CountOfNeighborInStates(int lower_state, int higher_state)
        {
            int result = 0;
            mut_sused.WaitOne();
            foreach(Neighbor nei in neighbors)
                if (nei.state >= lower_state && nei.state <= higher_state)
                    result++;
            mut_sused.ReleaseMutex();
            return result;
        }

        public ushort Fletcher(byte[] inputAsBytes, int start, int length)
        {
            int c0 = 0, c1 = 0;
            for (int i = start; i < length; ++i)
            {
                c0 = (c0 + inputAsBytes[i]) % 255;
                c1 = (c1 + c0) % 255;
            }
            int x = ((c1 * -1) + ((length - 15 - start) * c0)) % 255;
            int y = (c1 - ((length - 15 + 1 - start) * c0)) % 255;
            if (x < 0) x += 255;
            if (y < 0) y += 255;
            return (ushort)((x << 8) | y);
        }

        public bool IsChecksumCorrect(byte[] b, int start, int length)
        {
            int c0 = 0, c1 = 0;
            for (int i = start; i < length; ++i)
            {
                c0 = (c0 + b[i]) % 255;
                c1 = (c1 + c0) % 255;
            }
            if (c0 == 0 && c1 == 0) return true;
            else return false;
        }
    }

    /*
     * ================================================================
     *              HLAVNY OVLADAC
     * ================================================================
     */

    public partial class MainWindow : Window
    {
        public Smerovac smerovac;
        public WinPcapDeviceList winlist;
        public bool stop;
        public Thread th_arp, th_sused, th_hello1, th_hello2, th_waitTimer1, th_waitTimer2, th_lsa;
        public Mutex mutex = new Mutex();
        public List<OSPFv2DDPacket> dd_processing;

        public MainWindow()
        {
            InitializeComponent();
            InitializeDevices();
            SetGui(Visibility.Visible, Visibility.Collapsed);
        }

        public void PacketArrival(object sender, CaptureEventArgs raw)
        {
            Port captured;
            if (smerovac.ports[0].port == (WinPcapDevice)sender)
                captured = smerovac.ports[0];
            else captured = smerovac.ports[1];

            var packet = Packet.ParsePacket(raw.Packet.LinkLayerType, raw.Packet.Data);
            if (packet is EthernetPacket eth_packet)
            {
                var arp_packet = (ARPPacket)eth_packet.Extract(typeof(ARPPacket));

                if (arp_packet != null)
                {
                    if (arp_packet.Operation == ARPOperation.Request)
                    {
                        if (arp_packet.TargetProtocolAddress.Equals(captured.ip_add))
                            PosliArpReply(captured, captured.ip_add, captured.port.MacAddress, arp_packet.SenderProtocolAddress, arp_packet.SenderHardwareAddress);
                        else if (ViemSmerovatDoSiete(arp_packet.TargetProtocolAddress, captured))
                            PosliArpReply(captured, arp_packet.TargetProtocolAddress, captured.port.MacAddress, arp_packet.SenderProtocolAddress, arp_packet.SenderHardwareAddress);
                        return;
                    } else if (arp_packet.Operation == ARPOperation.Response && arp_packet.TargetProtocolAddress.Equals(captured.ip_add))
                    {
                        PridajArpZaznam(arp_packet.SenderProtocolAddress, arp_packet.SenderHardwareAddress);
                        return;
                    }
                }

                var ip_packet = (IPv4Packet)eth_packet.Extract(typeof(IPv4Packet));

                if (ip_packet != null)
                {
                    var ospf_packet = (OSPFv2Packet)ip_packet.Extract(typeof(OSPFv2Packet));

                    if (ospf_packet != null)
                    {
                        if (!captured.ospf) return;
                        if (!smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(captured)).Equals(captured.ip_add) && !smerovac.ospf.BDRs.ElementAt(smerovac.ports.IndexOf(captured)).Equals(captured.ip_add) && ip_packet.DestinationAddress.Equals(IPAddress.Parse("224.0.0.6")))
                        {
                            Console.WriteLine("Neprijmam!!");
                            return;
                        }
                        if (ospf_packet.Type == OSPFPacketType.Hello)
                        {
                            OSPFv2HelloPacket hello = (OSPFv2HelloPacket)ospf_packet;
                            Console.WriteLine("Dostal som hello " + hello.RouterID);
                            Console.WriteLine("" + ip_packet.SourceAddress + " - " + hello.RouterID + " - ARRIVAL");
                            PridajSuseda(hello, ip_packet.SourceAddress, eth_packet.SourceHwAddress, captured);
                            if (smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(captured)).Equals(IPAddress.Parse("0.0.0.0")) &&
                                smerovac.ospf.BDRs.ElementAt(smerovac.ports.IndexOf(captured)).Equals(IPAddress.Parse("0.0.0.0")))
                            {
                                if (hello.BackupRouterID.Equals(ip_packet.SourceAddress) ||
                                    (hello.DesignatedRouterID.Equals(ip_packet.SourceAddress) && hello.BackupRouterID.Equals(IPAddress.Parse("0.0.0.0"))))
                                {
                                    if (hello.NeighborID.Contains(smerovac.routerID))
                                    {
                                        captured.need_calculation = false;
                                        smerovac.mut_sused.WaitOne();
                                        Console.WriteLine("8");
                                        MakeElection(captured);
                                        smerovac.mut_sused.ReleaseMutex();
                                    }
                                }
                            }
                        }
                        else if (ospf_packet.Type == OSPFPacketType.DatabaseDescription && ip_packet.DestinationAddress.Equals(captured.ip_add))
                        {
                            Console.WriteLine("Dostal som DBD " + ip_packet.SourceAddress);
                            OSPFv2DDPacket dd = (OSPFv2DDPacket)ospf_packet;
                            smerovac.mut_sused.WaitOne();
                            Neighbor neighbor = GetNeighbor(ospf_packet.RouterID, ip_packet.SourceAddress);
                            smerovac.mut_sused.ReleaseMutex();
                            if (neighbor != null)
                            {
                                if (neighbor.state == 3) // STATE EXSTART
                                {
                                    if (dd.DBDescriptionBits == 7 && dd.LSAHeader.Count == 0 && neighbor.master)
                                    {
                                        neighbor.last_r = dd;
                                        neighbor.dd_seq = dd.DDSequence;
                                        neighbor.state = 4;
                                    }
                                    else if (dd.DBDescriptionBits == 2 && dd.DDSequence == neighbor.dd_seq && !neighbor.master)
                                    {
                                        neighbor.last_r = dd;
                                        neighbor.dd_seq++;
                                        neighbor.state = 4;
                                        ProcessDBD(neighbor, dd.LSAHeader);
                                    }
                                    else return;
                                }
                                else if (neighbor.state == 4) // STATE EXCHANGE
                                {
                                    if (!neighbor.master && neighbor.last_r.DBDescriptionBits == dd.DBDescriptionBits && neighbor.last_r.DBDescriptionOptions == dd.DBDescriptionOptions &&
                                        neighbor.last_r.DDSequence == dd.DDSequence) return;

                                    bool ms_bit = GetBitFromByte(dd.DBDescriptionBits, 1);
                                    bool i_bit = GetBitFromByte(dd.DBDescriptionBits, 3);

                                    if (ms_bit != neighbor.master || i_bit || neighbor.last_r.DBDescriptionOptions != dd.DBDescriptionOptions)
                                    {
                                        SeqNumberMismatch(neighbor);
                                        return;
                                    }

                                    if ((!neighbor.master && dd.DDSequence == neighbor.last_s.DDSequence) || (neighbor.master && neighbor.last_s.DDSequence + 1 == dd.DDSequence))
                                    {
                                        ProcessDBD(neighbor, dd.LSAHeader);
                                        if (neighbor.master)
                                        {
                                            if (neighbor.last_r.DBDescriptionBits == dd.DBDescriptionBits && neighbor.last_r.DBDescriptionOptions == dd.DBDescriptionOptions &&
                                                neighbor.last_r.DDSequence == dd.DDSequence)
                                            {
                                                SendLastSendDD(neighbor, eth_packet.SourceHwAddress);
                                            }
                                            else {
                                                neighbor.dd_seq = dd.DDSequence;
                                                neighbor.last_r = dd;
                                                if (neighbor.last_s.DBDescriptionBits == 0 && dd.DBDescriptionBits == 1)
                                                {
                                                    neighbor.state = 5;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            neighbor.dd_seq++;
                                            neighbor.last_r = dd;
                                            if (dd.DBDescriptionBits == 0 && neighbor.last_s.DBDescriptionBits == 1) {
                                                neighbor.state = 5;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        SeqNumberMismatch(neighbor);
                                        return;
                                    }
                                }
                                else if (neighbor.state == 5 || neighbor.state == 6) // STATE LOADING OR FULL
                                {
                                    bool i_bit = GetBitFromByte(dd.DBDescriptionBits, 3);

                                    if (i_bit)
                                    {
                                        if (neighbor.state == 6)
                                        {
                                            neighbor.state = 3;
                                            smerovac.mut_sused.WaitOne();
                                            MakeRouterLSA(captured, smerovac.ospf.DRs[smerovac.ports.IndexOf(captured)]);
                                            if (smerovac.ospf.DRs[smerovac.ports.IndexOf(captured)].Equals(captured.ip_add))
                                                MakeNetworkLSA(captured, smerovac.ospf.DRs[smerovac.ports.IndexOf(captured)]);
                                            smerovac.mut_sused.ReleaseMutex();
                                        }
                                        SeqNumberMismatch(neighbor);
                                        return;
                                    }

                                    if (neighbor.master && neighbor.last_r.DBDescriptionBits == dd.DBDescriptionBits && neighbor.last_r.DBDescriptionOptions == dd.DBDescriptionOptions &&
                                        neighbor.last_r.DDSequence == dd.DDSequence)
                                    {
                                        SendLastSendDD(neighbor, eth_packet.SourceHwAddress);
                                    }
                                }
                            }
                        }
                        else if (ospf_packet.Type == OSPFPacketType.LinkStateRequest && ip_packet.DestinationAddress.Equals(captured.ip_add))
                        {
                            Console.WriteLine("Dostal som REQUEST " + ip_packet.SourceAddress);
                            OSPFv2LSRequestPacket request = (OSPFv2LSRequestPacket)ospf_packet;
                            smerovac.mut_sused.WaitOne();
                            Neighbor neighbor = GetNeighbor(ospf_packet.RouterID, ip_packet.SourceAddress);
                            smerovac.mut_sused.ReleaseMutex();

                            if (neighbor == null || neighbor.state < 4) return;

                            SendRequestedLSAs(neighbor, request, eth_packet.SourceHwAddress);
                        }
                        else if (ospf_packet.Type == OSPFPacketType.LinkStateUpdate)
                        {
                            Console.WriteLine("Dostal som UPDATE " + ip_packet.SourceAddress);
                            OSPFv2LSUpdatePacket update = (OSPFv2LSUpdatePacket)ospf_packet;
                            smerovac.mut_sused.WaitOne();
                            Neighbor neighbor = GetNeighbor(ospf_packet.RouterID, ip_packet.SourceAddress);
                            smerovac.mut_sused.ReleaseMutex();

                            if (neighbor == null || neighbor.state < 4) return;
                            mutex.WaitOne();
                            ProcessLSU(neighbor, update.LSAUpdates, captured, ip_packet.SourceAddress, eth_packet.SourceHwAddress);
                            mutex.ReleaseMutex();
                        }
                        else if (ospf_packet.Type == OSPFPacketType.LinkStateAcknowledgment)
                        {
                            Console.WriteLine("Dostal som ACK " + ip_packet.SourceAddress);
                            OSPFv2LSAPacket ack = (OSPFv2LSAPacket)ospf_packet;
                            smerovac.mut_sused.WaitOne();
                            Neighbor neighbor = GetNeighbor(ospf_packet.RouterID, ip_packet.SourceAddress);
                            smerovac.mut_sused.ReleaseMutex();

                            if (neighbor == null || neighbor.state < 4) return;

                            foreach (LSA lsa in ack.LSAAcknowledge)
                            {
                                neighbor.RemoveRetransLSA(lsa);
                            }
                        }
                        return;
                    }

                    Port output;
                    IPAddress nexthop;
                    Tuple<IPAddress, Port> ret;
                    // ROUTING TABLE LOOKUP
                    ret = IPLookup(ip_packet.DestinationAddress, ip_packet.DestinationAddress);
                    if (ret == null || ret.Item2 == captured)
                        return;
                    nexthop = ret.Item1;
                    output = ret.Item2;
                    // ARP TABLE LOOKUP
                    PhysicalAddress mac = ARPLookup(nexthop);
                    if (mac != null)
                    {
                        EthernetPacket ethernet = new EthernetPacket(output.port.MacAddress, mac, eth_packet.Type);
                        if (--ip_packet.TimeToLive == 0) return;
                        ip_packet.UpdateIPChecksum();
                        ethernet.PayloadPacket = ip_packet;
                        output.port.SendPacket(ethernet);
                    } else PosliArpRequest(output, nexthop);
                }
            }
        }

        public IPAddress IPtoNet(IPAddress ip, IPAddress mask)
        {
            byte[] bip = ip.GetAddressBytes();
            byte[] bmask = mask.GetAddressBytes();
            byte[] res = new byte[4];

            for (int i = 0; i < 4; i++)
                res[i] = (byte)((int)bip[i] & (int)bmask[i]);

            return new IPAddress(res);
        }

        public void SeqNumberMismatch(Neighbor neighbor)
        {
            neighbor.dd_seq++;
            neighbor.state = 3;
            Thread th = new Thread(() => ExStart(neighbor));
            th.Start();
        }

        public bool GetBitFromByte(byte b, int pozicia) => (b & (1 << pozicia - 1)) != 0;

        /*
         * ================================================================
         *          GUI
         * ================================================================
         */

        public void Start(object sender, RoutedEventArgs e)
        {
            if (Listbox1.SelectedIndex != Listbox2.SelectedIndex && Listbox1.SelectedIndex != -1 && Listbox2.SelectedIndex != -1)
            {
                SetGui(Visibility.Collapsed, Visibility.Visible, winlist.ElementAt(Listbox1.SelectedIndex).Description, winlist.ElementAt(Listbox2.SelectedIndex).Description);
                stop = false;
                th_arp = new Thread(() => VypisArpTabulky());
                th_sused = new Thread(() => VypisSusedov());
                th_lsa = new Thread(() => IncrementLsaAge());
                dd_processing = new List<OSPFv2DDPacket>();
                smerovac = new Smerovac(winlist[Listbox1.SelectedIndex], winlist[Listbox2.SelectedIndex]);
                OtvorPorty();
                th_arp.Start();
                th_sused.Start();
                th_lsa.Start();
            }
        }

        public void Stop(object sender, RoutedEventArgs e)
        {
            stop = true;
            th_arp.Join();
            th_sused.Join();
            InitializeDevices();
            SetGui(Visibility.Visible, Visibility.Collapsed);
        }

        public void InitializeDevices()
        {
            winlist = WinPcapDeviceList.Instance;
            Listbox1.Items.Clear();
            Listbox2.Items.Clear();
            foreach (WinPcapDevice dev in winlist)
            {
                Listbox1.Items.Add(dev.Description);
                Listbox2.Items.Add(dev.Description);
            }
        }

        public void SetGui(Visibility vis_interface, Visibility vis_router, params String[] e)
        {
            InterfacesStackPanel.Visibility = vis_interface;
            RouterStackPanel.Visibility = vis_router;
            if (e.Length == 2)
            {
                Port1_name.Content = e[0];
                Port2_name.Content = e[1];

                StaticRoutePort.Items.Add(e[0]);
                StaticRoutePort.Items.Add(e[1]);
                StaticRoutePort.Items.Add("Žiadny");
            }
        }

        /*
         * ================================================================
         *          OSPF
         * ================================================================
         */

        public void MakeNetworkLSA(Port port, IPAddress dr)
        {
            uint old_seq = 0x80000000;
            List<IPAddress> routers = FullNeighbor(port);

            if (routers.Count == 0) return;
            NetworkLSA net = null;
            smerovac.mut_database.WaitOne();

            if (smerovac.my_network_lsa.Count > 0)
            {
                foreach (NetworkLSA n in smerovac.my_network_lsa)
                    if (n.LinkStateID.Equals(port.ip_add)) net = n;
            }

            if (net != null)
            {
                old_seq = net.LSSequenceNumber;
                smerovac.my_network_lsa.Remove(net);
            }

            routers.Add(smerovac.routerID);
            net = new NetworkLSA(routers)
            {
                Options = 2,
                LSAge = 0,
                LinkStateID = dr,
                AdvertisingRouter = smerovac.routerID,
                LSSequenceNumber = old_seq + 1,
                Checksum = 0,
                NetworkMask = port.maska
            };
            net.Checksum = smerovac.Fletcher(net.Bytes, 2, net.Length);
            smerovac.my_network_lsa.Add(net);
            Flood(net, null, null, null);
            smerovac.mut_database.ReleaseMutex();
            DatabaseRecord old = smerovac.GetInstanceOfLSA(net);
            Install(net, old);
        }

        public void FlushNetworkLSA(Port port)
        {
            smerovac.mut_database.WaitOne();
            NetworkLSA net = null;
            if (smerovac.my_network_lsa.Count > 0)
            {
                foreach (NetworkLSA n in smerovac.my_network_lsa)
                    if (n.LinkStateID.Equals(port.ip_add)) net = n;
            }
            if (net != null)
            {
                smerovac.my_network_lsa.Remove(net);
                net.LSAge = 3600;
                Flood(net, null, null, null);
            }
            smerovac.mut_database.ReleaseMutex();
        }

        public void MakeRouterLSA(Port port, IPAddress dr)
        {
            int count = FullNeighbor(port).Count;
            Neighbor neighbor = GetNeighbor(null, dr);
            
            if (dr.Equals(IPAddress.Parse("0.0.0.0")))
                MakeStub(port);
            else if ((!port.ip_add.Equals(dr) && neighbor.state == 6) || (port.ip_add.Equals(dr) && count > 0))
                MakeTransit(port, dr);
            else MakeStub(port);
        }

        public void MakeStub(Port port)
        {
            smerovac.mut_database.WaitOne();
            bool need_new = false;
            RouterLink link = null;
            foreach (RouterLink l in smerovac.links)
            {
                if ((l.Type == 2 && l.LinkData.Equals(port.ip_add)) || (l.Type == 3 && l.LinkID.Equals(IPtoNet(port.ip_add, port.maska))))
                {
                    link = l;
                    break;
                }
            }

            if (link != null)
            {
                if (link.Type == 2) need_new = true;
                else if (!link.LinkID.Equals(IPtoNet(port.ip_add, port.maska))) need_new = true;
                else if (!link.LinkData.Equals(port.maska)) need_new = true;
                else if (link.Metric != (ushort)port.cost) need_new = true;
                if (need_new) smerovac.links.Remove(link);
                if (!port.ospf)
                {
                    need_new = true;
                    smerovac.links.Remove(link);
                }
            }
            else need_new = true;

            if (need_new)
            {
                if (port.ospf)
                {
                    smerovac.links.Add(new RouterLink()
                    {
                        LinkID = IPtoNet(port.ip_add, port.maska),
                        LinkData = port.maska,
                        Type = 3,
                        Metric = (ushort)port.cost
                    });
                }

                uint old_seq = 0x80000000;
                if (smerovac.my_lsa != null)
                {
                    old_seq = smerovac.my_lsa.LSSequenceNumber;
                }
                smerovac.my_lsa = new RouterLSA(smerovac.links)
                {
                    Options = 2,
                    LSAge = 0,
                    LinkStateID = smerovac.routerID,
                    AdvertisingRouter = smerovac.routerID,
                    LSSequenceNumber = old_seq + 1,
                    Checksum = 0,
                    VBit = 0,
                    EBit = 0,
                    BBit = 0
                };
                smerovac.my_lsa.Checksum = smerovac.Fletcher(smerovac.my_lsa.Bytes, 2, smerovac.my_lsa.Length);
                //smerovac.my_database.Add(new DatabaseRecord(smerovac.my_lsa));
                Flood(smerovac.my_lsa, null, null, null);
                smerovac.mut_database.ReleaseMutex();
                DatabaseRecord old = smerovac.GetInstanceOfLSA(smerovac.my_lsa);
                Install(smerovac.my_lsa, old);
            } else smerovac.mut_database.ReleaseMutex();
        }

        public void MakeTransit(Port port, IPAddress dr)
        {
            smerovac.mut_database.WaitOne();
            bool need_new = false;
            RouterLink link = null;
            foreach (RouterLink l in smerovac.links)
            {
                if ((l.Type == 2 && l.LinkData.Equals(port.ip_add)) || (l.Type == 3 && l.LinkID.Equals(IPtoNet(port.ip_add, port.maska))))
                {
                    link = l;
                    break;
                }
            }

            if (link != null)
            {
                if (link.Type == 3) need_new = true;
                else if (!link.LinkID.Equals(dr)) need_new = true;
                else if (!link.LinkData.Equals(port.ip_add)) need_new = true;
                else if (link.Metric != (ushort)port.cost) need_new = true;
                if (need_new) smerovac.links.Remove(link);
                if (!port.ospf)
                {
                    need_new = true;
                    smerovac.links.Remove(link);
                }
            }
            else need_new = true;

            if (need_new)
            {
                if (port.ospf)
                {
                    smerovac.links.Add(new RouterLink()
                    {
                        LinkID = dr,
                        LinkData = port.ip_add,
                        Type = 2,
                        Metric = (ushort)port.cost
                    });
                }

                uint old_seq = 0x80000000;
                if (smerovac.my_lsa != null)
                {
                    old_seq = smerovac.my_lsa.LSSequenceNumber;
                }
                smerovac.my_lsa = new RouterLSA(smerovac.links)
                {
                    Options = 2,
                    LSAge = 0,
                    LinkStateID = smerovac.routerID,
                    AdvertisingRouter = smerovac.routerID,
                    LSSequenceNumber = old_seq + 1,
                    Checksum = 0,
                    VBit = 0,
                    EBit = 0,
                    BBit = 0
                };
                smerovac.my_lsa.Checksum = smerovac.Fletcher(smerovac.my_lsa.Bytes, 2, smerovac.my_lsa.Length);
                Flood(smerovac.my_lsa, null, null, null);
                smerovac.mut_database.ReleaseMutex();
                DatabaseRecord old = smerovac.GetInstanceOfLSA(smerovac.my_lsa);
                Install(smerovac.my_lsa, old);
            }
            else smerovac.mut_database.ReleaseMutex();
        }

        public void IncrementLsaAge()
        {
            List<DatabaseRecord> vymazat = new List<DatabaseRecord>();
            while (!stop)
            {
                smerovac.mut_database.WaitOne();
                DatabaseListbox.Dispatcher.Invoke(() =>
                {
                    DatabaseListbox.Items.Clear();
                });
                foreach (DatabaseRecord lsa in smerovac.my_database)
                {
                    ++lsa.learned;
                    if (lsa.lsa.LSAge == 3600)
                    {
                        if (!vymazat.Contains(lsa)) vymazat.Add(lsa);
                    }
                    else if (lsa.lsa.LSAge == 1800)
                    {
                        if (lsa.lsa.AdvertisingRouter.Equals(smerovac.routerID) || (lsa.lsa.LSType == LSAType.Network && (lsa.lsa.LinkStateID.Equals(smerovac.GetPortAt(0).ip_add) || lsa.lsa.LinkStateID.Equals(smerovac.GetPortAt(1).ip_add))))
                        {
                            lsa.lsa.LSAge = 0;
                            lsa.lsa.LSSequenceNumber += 1;
                            Flood(lsa.lsa, null, null, null);
                        }
                    }
                    else
                    {
                        ++lsa.lsa.LSAge;
                        DatabaseListbox.Dispatcher.Invoke(() =>
                        {
                            DatabaseListbox.Items.Add(lsa.lsa.LSAge + "\t" + lsa.lsa.LSType + "\t" + lsa.lsa.LinkStateID + "\t" + lsa.lsa.AdvertisingRouter + "\t" + lsa.lsa.LSSequenceNumber.ToString("X") + "\t" + lsa.learned);
                        });
                    }
                }
                bool contained = false;
                foreach (DatabaseRecord lsa in vymazat)
                {
                    smerovac.mut_sused.WaitOne();
                    foreach (Neighbor nei in smerovac.neighbors)
                    {
                        if (nei.IsInstanceInRetransList(lsa.lsa))
                        {
                            contained = true;
                            break;
                        }
                    }
                    smerovac.mut_sused.ReleaseMutex();
                    int count = smerovac.CountOfNeighborInStates(4, 5);
                    if (!contained && count == 0)
                    {
                        smerovac.my_database.Remove(lsa);
                    }
                }
                smerovac.mut_database.ReleaseMutex();
                Thread.Sleep(1000);
            }
        }

        public void OspfPort1(object sender, RoutedEventArgs e)
        {
            if (OspfButt1.Content.Equals("Zapnúť OSPF na porte 1"))
            {
                smerovac.GetPortAt(0).ospf = true;
                th_hello1 = new Thread(() => PosliHello(smerovac.GetPortAt(0)));
                th_waitTimer1 = new Thread(() => WaitTimer(smerovac.GetPortAt(0)));
                new Thread(() =>
                {
                    smerovac.mut_sused.WaitOne();
                    MakeRouterLSA(smerovac.GetPortAt(0), smerovac.ospf.DRs[smerovac.ports.IndexOf(smerovac.GetPortAt(0))]);
                    smerovac.mut_sused.ReleaseMutex();
                }).Start();
                th_hello1.Start();
                th_waitTimer1.Start();
                OspfButt1.Content = "Vypnúť OSPF na porte 1";
            } else
            {
                smerovac.GetPortAt(0).ospf = false;
                smerovac.mut_sused.WaitOne();
                MakeRouterLSA(smerovac.GetPortAt(0), smerovac.ospf.DRs[smerovac.ports.IndexOf(smerovac.GetPortAt(0))]);
                smerovac.mut_sused.ReleaseMutex();
                //th_hello1.Join();
                th_hello1 = null;
                //th_waitTimer1.Join();
                th_waitTimer1 = null;
                OspfButt1.Content = "Zapnúť OSPF na porte 1";
            }
        }

        public void OspfPort2(object sender, RoutedEventArgs e)
        {
            if (OspfButt2.Content.Equals("Zapnúť OSPF na porte 2"))
            {
                smerovac.GetPortAt(1).ospf = true;
                th_hello2 = new Thread(() => PosliHello(smerovac.GetPortAt(1)));
                th_waitTimer2 = new Thread(() => WaitTimer(smerovac.GetPortAt(1)));
                new Thread(() =>
                {
                    smerovac.mut_sused.WaitOne();
                    MakeRouterLSA(smerovac.GetPortAt(1), smerovac.ospf.DRs[smerovac.ports.IndexOf(smerovac.GetPortAt(1))]);
                    smerovac.mut_sused.ReleaseMutex();
                }).Start();
                th_hello2.Start();
                th_waitTimer2.Start();
                OspfButt2.Content = "Vypnúť OSPF na porte 2";
            }
            else
            {
                smerovac.GetPortAt(1).ospf = false;
                smerovac.mut_sused.WaitOne();
                MakeRouterLSA(smerovac.GetPortAt(1), smerovac.ospf.DRs[smerovac.ports.IndexOf(smerovac.GetPortAt(1))]);
                smerovac.mut_sused.ReleaseMutex();
                //th_hello2.Join();
                th_hello2 = null;
                //th_waitTimer2.Join();
                th_waitTimer2 = null;
                OspfButt2.Content = "Zapnúť OSPF na porte 2";
            }
        }

        public Neighbor GetNeighbor(IPAddress router_id, IPAddress ip)
        {
            foreach (Neighbor nei in smerovac.neighbors)
                if ((router_id == null && nei.ip_add.Equals(ip)) || (nei.neighbor_id.Equals(router_id) && nei.ip_add.Equals(ip)))
                {
                    return nei;
                }
            return null;
        }

        public List<IPAddress> FullNeighbor(Port port)
        {
            List<IPAddress> ret = new List<IPAddress>();
            foreach (Neighbor nei in smerovac.neighbors)
                if (nei.state == 6 && nei.output == port) ret.Add(nei.neighbor_id);
            return ret;
        }

        public void WaitTimer(Port port)
        {
            Thread.Sleep(40000);
            //smerovac.neighbors.Add(new Neighbor(IPAddress.Parse("2.2.2.2"), IPAddress.Parse("100.100.100.102"), 2, 10, 2, port,IPAddress.Parse("0.0.0.0"), IPAddress.Parse("0.0.0.0")));
            //smerovac.neighbors.Add(new Neighbor(IPAddress.Parse("4.4.4.4"), IPAddress.Parse("100.100.100.104"), 1, 40, 2, port, IPAddress.Parse("0.0.0.0"), IPAddress.Parse("0.0.0.0")));
            //smerovac.neighbors.Add(new Neighbor(IPAddress.Parse("6.6.6.6"), IPAddress.Parse("100.100.100.106"), 1, 30, 2, port, IPAddress.Parse("0.0.0.0"), IPAddress.Parse("0.0.0.0")));
            //smerovac.neighbors.Add(new Neighbor(IPAddress.Parse("8.8.8.8"), IPAddress.Parse("100.100.100.108"), 1, 20, 2, port, IPAddress.Parse("0.0.0.0"), IPAddress.Parse("0.0.0.0")));
            if (port.ospf && port.need_calculation)
            {
                Console.WriteLine("9");
                smerovac.mut_sused.WaitOne();
                MakeElection(port);
                smerovac.mut_sused.ReleaseMutex();
                port.need_calculation = false;
            }
        }

        public void MakeElection(Port port)
        {
            IPAddress actualDR = smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(port)),
                actualBDR = smerovac.ospf.BDRs.ElementAt(smerovac.ports.IndexOf(port));
            Tuple<IPAddress, IPAddress> result = Election(port);
            System.Diagnostics.Trace.WriteLine("ELECTED ===\nDR: " + result.Item1 + "\nBDR: " + result.Item2);
            if ((actualDR.Equals(port.ip_add) && !result.Item1.Equals(actualDR)) || (actualBDR.Equals(port.ip_add) && !result.Item2.Equals(actualBDR))
                || (!actualDR.Equals(port.ip_add) && result.Item1.Equals(port.ip_add)) || (!actualBDR.Equals(port.ip_add) && result.Item2.Equals(port.ip_add)))
            {
                smerovac.ospf.DRs[smerovac.ports.IndexOf(port)] = result.Item1;
                smerovac.ospf.BDRs[smerovac.ports.IndexOf(port)] = result.Item2;
                result = Election(port);
                System.Diagnostics.Trace.WriteLine("ELECTED ===\nDR: " + result.Item1 + "\nBDR: " + result.Item2);
            }
            smerovac.ospf.DRs[smerovac.ports.IndexOf(port)] = result.Item1;
            smerovac.ospf.BDRs[smerovac.ports.IndexOf(port)] = result.Item2;
            
            ChangeAdj(result.Item1, result.Item2, port);
            MakeRouterLSA(port, result.Item1);
            int count = FullNeighbor(port).Count;
            if (port.ip_add.Equals(result.Item1) && count == 0) FlushNetworkLSA(port);
            if (port.ip_add.Equals(actualDR) && !port.ip_add.Equals(result.Item1)) FlushNetworkLSA(port); // NO LONGER DR
            if (!port.ip_add.Equals(actualDR) && port.ip_add.Equals(result.Item1)) MakeNetworkLSA(port, result.Item1); // NEW DR
        }

        public void ChangeAdj(IPAddress dr, IPAddress bdr, Port port)
        {
            if (dr.Equals(port.ip_add)) // AK SOM DR
            {
                foreach (Neighbor nei in smerovac.neighbors)
                {
                    if (nei.output == port)
                    {
                        if (nei.ip_add.Equals(bdr))
                            nei.typ = 'B';
                        else nei.typ = 'O';
                        if (nei.state == 2)
                        {
                            nei.state = 3;
                            Thread thread = new Thread(() => ExStart(nei));
                            //dd_thread.Add(thread);
                            thread.Start();
                        }
                    }
                }
            }
            else if (bdr.Equals(port.ip_add)) // AK SOM BDR
            {
                foreach (Neighbor nei in smerovac.neighbors)
                {
                    if (nei.output == port)
                    {
                        if (nei.ip_add.Equals(dr))
                            nei.typ = 'D';
                        else nei.typ = 'O';
                        if (nei.state == 2)
                        {
                            nei.state = 3;
                            Thread thread = new Thread(() => ExStart(nei));
                            //dd_thread.Add(thread);
                            thread.Start();
                        }
                    }
                }
            }
            else // AK NIE SOM DR/BDR
            {
                foreach (Neighbor nei in smerovac.neighbors)
                {
                    if (nei.output == port)
                    {
                        if (nei.ip_add.Equals(dr))
                        {
                            nei.typ = 'D';
                            if (nei.state == 2)
                            {
                                nei.state = 3;
                                Thread thread = new Thread(() => ExStart(nei));
                                //dd_thread.Add(thread);
                                thread.Start();
                            }
                        }
                        else if (nei.ip_add.Equals(bdr))
                        {
                            nei.typ = 'B';
                            if (nei.state == 2)
                            {
                                nei.state = 3;
                                Thread thread = new Thread(() => ExStart(nei));
                                //dd_thread.Add(thread);
                                thread.Start();
                            }
                        }
                        else
                        {
                            nei.typ = 'O';
                            if (nei.state > 2) nei.state = 2;
                        }
                    }
                }
            }
        }

        public Tuple<IPAddress, IPAddress> Election(Port port)
        {
            IPAddress actualDR = smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(port)),
                actualBDR = smerovac.ospf.BDRs.ElementAt(smerovac.ports.IndexOf(port));
            List<Neighbor> candidates = new List<Neighbor>();
            bool possibleDR = false, possibleBDR = false;

            Neighbor BDR = null, DR = null;

            candidates.Add(new Neighbor(smerovac.routerID, port.ip_add, smerovac.ospf.priority, smerovac.ospf.dead_interval, 0, port, actualDR, actualBDR, false, 0));

            if (actualDR.Equals(port.ip_add)) possibleDR = true;
            if (actualBDR.Equals(port.ip_add) && !actualDR.Equals(port.ip_add)) possibleBDR = true;

            foreach (Neighbor n in smerovac.neighbors)
                if (n.output == port && n.priority > 0 && n.state > 1)
                {
                    candidates.Add(n);
                    if (n.bdr.Equals(n.ip_add) && !actualDR.Equals(n.ip_add)) possibleBDR = true;
                    if (n.dr.Equals(n.ip_add)) possibleDR = true;
                }

            foreach (Neighbor n in candidates)
            {
                if (!n.dr.Equals(n.ip_add))
                {
                    if (possibleBDR)
                    {
                        if (n.bdr.Equals(n.ip_add))
                        {
                            if (BDR != null)
                            {
                                if (n.priority > BDR.priority || (n.priority == BDR.priority && smerovac.GreaterIP(n.neighbor_id, BDR.neighbor_id).Equals(n.neighbor_id)))
                                {
                                    BDR = n;
                                }
                            }
                            else BDR = n;
                        }
                    }
                    else
                    {
                        if (BDR != null)
                        {
                            if (n.priority > BDR.priority || (n.priority == BDR.priority && smerovac.GreaterIP(n.neighbor_id, BDR.neighbor_id).Equals(n.neighbor_id)))
                            {
                                BDR = n;
                            }
                        }
                        else BDR = n;
                    }
                }
            }

            if (possibleDR)
            {
                foreach (Neighbor n in candidates)
                    if (n.dr.Equals(n.ip_add))
                    {
                        if (DR != null)
                        {
                            if (n.priority > DR.priority || (n.priority == DR.priority && smerovac.GreaterIP(n.neighbor_id, DR.neighbor_id).Equals(n.neighbor_id)))
                            {
                                DR = n;
                            }
                        }
                        else DR = n;
                    }
            } else DR = BDR;

            if (BDR == null)
                return Tuple.Create(DR.ip_add, IPAddress.Parse("0.0.0.0"));
            else return Tuple.Create(DR.ip_add, BDR.ip_add);
        }

        public void PosliHello(Port port)
        {
            EthernetPacket eth = new EthernetPacket(port.port.MacAddress, PhysicalAddress.Parse("01-00-5E-00-00-05"), EthernetPacketType.IPv4);
            IPv4Packet ip = new IPv4Packet(port.ip_add, IPAddress.Parse("224.0.0.5"))
            {
                TimeToLive = 1
            };
            List<IPAddress> neighbors = new List<IPAddress>();
            OSPFv2HelloPacket hello = new OSPFv2HelloPacket(port.maska, 10, 40, neighbors)
            {
                AreaID = smerovac.ospf.AreaID,
                RtrPriority = smerovac.ospf.priority,
                HelloOptions = 2,
                RouterID = smerovac.routerID,
                DesignatedRouterID = smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(port)),
                BackupRouterID = smerovac.ospf.BDRs.ElementAt(smerovac.ports.IndexOf(port))
            };

            ip.PayloadPacket = hello;
            eth.PayloadPacket = ip;
            while (port.ospf)
            {
                hello.DesignatedRouterID = smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(port));
                hello.BackupRouterID = smerovac.ospf.BDRs.ElementAt(smerovac.ports.IndexOf(port));
                hello.RtrPriority = smerovac.ospf.priority;

                neighbors.Clear();

                smerovac.mut_sused.WaitOne();
                foreach (Neighbor n in smerovac.neighbors)
                    if (n.output == port)
                        neighbors.Add(n.neighbor_id);
                smerovac.mut_sused.ReleaseMutex();

                hello = new OSPFv2HelloPacket(port.maska, 10, 40, neighbors)
                {
                    AreaID = smerovac.ospf.AreaID,
                    RtrPriority = smerovac.ospf.priority,
                    HelloOptions = 2,
                    RouterID = smerovac.routerID,
                    DesignatedRouterID = smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(port)),
                    BackupRouterID = smerovac.ospf.BDRs.ElementAt(smerovac.ports.IndexOf(port))
                };
                ip.PayloadPacket = hello;

                ip.Checksum = 0;
                ip.UpdateIPChecksum();

                hello.Checksum = 0;
                hello.Checksum = smerovac.ComputeChecksum(hello.HeaderData, 0, hello.HeaderData.Length);

                port.port.SendPacket(eth);
                Thread.Sleep(10000);
            }
            Console.WriteLine("Skoncil som");
        }

        public void VymazSusedov(Port port)
        {
            bool need_calculation = false;
            List<Neighbor> vymazat = new List<Neighbor>();
            smerovac.mut_sused.WaitOne();
            foreach (Neighbor n in smerovac.neighbors)
                if (n.output == port)
                    vymazat.Add(n);

            foreach (Neighbor n in vymazat)
            {
                if (n.state == 6) need_calculation = true;
                smerovac.neighbors.Remove(n);
            }
            smerovac.mut_sused.ReleaseMutex();

            if (need_calculation)
            {
                MakeRouterLSA(port, smerovac.ospf.DRs[smerovac.ports.IndexOf(port)]);
                if (smerovac.ospf.DRs[smerovac.ports.IndexOf(port)].Equals(port.ip_add))
                    MakeNetworkLSA(port, smerovac.ospf.DRs[smerovac.ports.IndexOf(port)]);
            }
        }

        public void PridajSuseda(OSPFv2HelloPacket hello, IPAddress ip, PhysicalAddress mac, Port port)
        {
            smerovac.mut_sused.WaitOne();
            Console.WriteLine("" + ip + " - " + hello.RouterID + " - MUTEX");
            foreach (Neighbor n in smerovac.neighbors)
                if (n.neighbor_id.Equals(hello.RouterID) && n.ip_add.Equals(ip))
                {
                    n.dead_time = hello.RouterDeadInterval;
                    n.output = port;
                    if (hello.NeighborID.Contains(smerovac.routerID) && n.state < 2)
                    {
                        n.state = 2;
                        if (!port.need_calculation)
                        {
                            Console.WriteLine("1");
                            MakeElection(port);
                        }
                    }
                    if (n.state >= 2 && !port.need_calculation)
                    {
                        if (!n.dr.Equals(hello.DesignatedRouterID) && hello.DesignatedRouterID.Equals(ip))
                        {
                            n.dr = hello.DesignatedRouterID;
                            n.bdr = hello.BackupRouterID;
                            Console.WriteLine("2");
                            MakeElection(port);
                        }
                        if (!n.bdr.Equals(hello.BackupRouterID) && hello.BackupRouterID.Equals(ip))
                        {
                            n.dr = hello.DesignatedRouterID;
                            n.bdr = hello.BackupRouterID;
                            Console.WriteLine("3");
                            MakeElection(port);
                        }

                        if (n.dr.Equals(ip) && !hello.DesignatedRouterID.Equals(ip))
                        {
                            n.dr = hello.DesignatedRouterID;
                            n.bdr = hello.BackupRouterID;
                            Console.WriteLine("4");
                            MakeElection(port);
                        }
                        if (n.bdr.Equals(ip) && !hello.BackupRouterID.Equals(ip))
                        {
                            n.dr = hello.DesignatedRouterID;
                            n.bdr = hello.BackupRouterID;
                            Console.WriteLine("5");
                            MakeElection(port);
                        }
                        if (n.priority != hello.RtrPriority)
                        {
                            n.priority = hello.RtrPriority;
                            n.dr = hello.DesignatedRouterID;
                            n.bdr = hello.BackupRouterID;
                            Console.WriteLine("6");
                            MakeElection(port);
                        }
                    }
                    smerovac.mut_sused.ReleaseMutex();
                    return;
                }
            bool master = smerovac.GreaterIP(smerovac.routerID, hello.RouterID).Equals(hello.RouterID) ? true : false;
            if (hello.NeighborID.Contains(smerovac.routerID))
            {
                smerovac.neighbors.Add(new Neighbor(hello.RouterID, ip, hello.RtrPriority, hello.RouterDeadInterval, 2, port, hello.DesignatedRouterID, hello.BackupRouterID, master, (uint)new Random().Next(9999)));
                if (!port.need_calculation)
                {
                    Console.WriteLine("7");
                    MakeElection(port);
                }
            }
            else smerovac.neighbors.Add(new Neighbor(hello.RouterID, ip, hello.RtrPriority, hello.RouterDeadInterval, 1, port, hello.DesignatedRouterID, hello.BackupRouterID, master, (uint)new Random().Next(9999)));
            smerovac.neighbors_changed = true;
            smerovac.mut_sused.ReleaseMutex();
        }

        public void VypisSusedov()
        {
            List<Neighbor> vymazat = new List<Neighbor>();
            while (!stop)
            {
                smerovac.mut_sused.WaitOne();
                NeighborListbox.Dispatcher.Invoke(() =>
                {
                    NeighborListbox.Items.Clear();
                });

                foreach (Neighbor nei in smerovac.neighbors)
                    if (--nei.dead_time == 0 || nei.state == 0)
                        vymazat.Add(nei);
                    else NeighborListbox.Dispatcher.Invoke(() =>
                    {
                        NeighborListbox.Items.Add(nei.Vypis());
                    });

                if (vymazat.Count() > 0) smerovac.neighbors_changed = true;

                foreach (Neighbor nei in vymazat)
                {
                    smerovac.neighbors.Remove(nei);
                    if (nei.state > 1) MakeElection(nei.output);
                }
                
                foreach (Neighbor nei in vymazat)
                {
                    if (nei.state == 6)
                    {
                        MakeRouterLSA(nei.output, smerovac.ospf.DRs[smerovac.ports.IndexOf(nei.output)]);
                        if (smerovac.ospf.DRs[smerovac.ports.IndexOf(nei.output)].Equals(nei.output.ip_add))
                            MakeNetworkLSA(nei.output, smerovac.ospf.DRs[smerovac.ports.IndexOf(nei.output)]);
                    }
                }
                smerovac.mut_sused.ReleaseMutex();
                vymazat.Clear();
                Thread.Sleep(1000);
            }
        }

        public void ExStart(Neighbor neighbor)
        {
            Console.WriteLine(neighbor.neighbor_id + " TRANSITION TO EXSTART");
            int timer = 1000;
            PhysicalAddress neighbor_mac = ARPLookup(neighbor.ip_add);
            while (neighbor_mac == null)
            {
                PosliArpRequest(neighbor.output, neighbor.ip_add);
                Thread.Sleep(1000);
                neighbor_mac = ARPLookup(neighbor.ip_add);
            }

            EthernetPacket eth = new EthernetPacket(neighbor.output.port.MacAddress, neighbor_mac, EthernetPacketType.IPv4);
            IPv4Packet ip = new IPv4Packet(neighbor.output.ip_add, neighbor.ip_add)
            {
                TimeToLive = 1,
                Checksum = 0
            };

            OSPFv2DDPacket dd = new OSPFv2DDPacket
            {
                AreaID = smerovac.ospf.AreaID,
                DDSequence = neighbor.dd_seq,
                InterfaceMTU = 1500,
                RouterID = smerovac.routerID,
                DBDescriptionOptions = 66,
                DBDescriptionBits = 7,
                Checksum = 0
            };

            eth.PayloadPacket = ip;
            ip.PayloadPacket = dd;
            dd.Checksum = smerovac.ComputeChecksum(dd.HeaderData, 0, dd.HeaderData.Length);
            ip.UpdateIPChecksum();

            neighbor.last_s = dd;
            neighbor.output.port.SendPacket(eth);

            while (neighbor.state == 3)
            {
                Thread.Sleep(100);
                if (neighbor.state < 3) return;
                if (--timer == 0)
                {
                    neighbor.state = 0;
                    return;
                }
                if (timer % 50 == 0 && timer >= 50) neighbor.output.port.SendPacket(eth);
            }
            ExChange(neighbor, eth);
        }

        public void ExChange(Neighbor neighbor, EthernetPacket eth)
        {
            Console.WriteLine(neighbor.neighbor_id + " TRANSITION TO EXCHANGE");
            List<LSA> list_to_send = new List<LSA>();
            LSA newLSA;

            smerovac.mut_database.WaitOne();

            foreach (DatabaseRecord lsa in smerovac.my_database)
            {
                if (lsa.lsa.LSAge != 3600) list_to_send.Add(lsa.lsa);
                else neighbor.AddToRetransList(lsa.lsa);
            }

            neighbor.summary_list = list_to_send;
            smerovac.mut_database.ReleaseMutex();

            if (neighbor.master) // WE ARE SLAVE
            {
                OSPFv2DDPacket dd_full = new OSPFv2DDPacket(neighbor.summary_list)
                {
                    AreaID = smerovac.ospf.AreaID,
                    DDSequence = neighbor.dd_seq,
                    InterfaceMTU = 1500,
                    RouterID = smerovac.routerID,
                    DBDescriptionOptions = 66,
                    DBDescriptionBits = 2,
                    Checksum = 0
                };

                dd_full.Checksum = smerovac.ComputeChecksum(dd_full.HeaderData, 0, dd_full.HeaderData.Length);
                eth.PayloadPacket.PayloadPacket = dd_full;
                ((IPv4Packet)eth.PayloadPacket).UpdateIPChecksum();
                neighbor.last_s = dd_full;
                neighbor.output.port.SendPacket(eth);

                while (neighbor.last_s.DDSequence + 1 != neighbor.last_r.DDSequence)
                {
                    Thread.Sleep(50);
                }

                OSPFv2DDPacket dd_empty = new OSPFv2DDPacket()
                {
                    AreaID = smerovac.ospf.AreaID,
                    DDSequence = neighbor.dd_seq,
                    InterfaceMTU = 1500,
                    RouterID = smerovac.routerID,
                    DBDescriptionOptions = 66,
                    DBDescriptionBits = 0,
                    Checksum = 0
                };

                dd_empty.Checksum = smerovac.ComputeChecksum(dd_empty.HeaderData, 0, dd_empty.HeaderData.Length);
                eth.PayloadPacket.PayloadPacket = dd_empty;
                ((IPv4Packet)eth.PayloadPacket).UpdateIPChecksum();
                neighbor.last_s = dd_empty;
                neighbor.output.port.SendPacket(eth);

                while (neighbor.state != 5)
                {
                    Thread.Sleep(50);
                }

                dd_empty.DDSequence = neighbor.dd_seq;
                dd_empty.Checksum = 0;
                dd_empty.Checksum = smerovac.ComputeChecksum(dd_empty.HeaderData, 0, dd_empty.HeaderData.Length);
                eth.PayloadPacket.PayloadPacket = dd_empty;
                ((IPv4Packet)eth.PayloadPacket).UpdateIPChecksum();
                neighbor.last_s = dd_empty;
                neighbor.output.port.SendPacket(eth);
            }
            else // WE ARE MASTER
            {
                int timer = 1000;
                OSPFv2DDPacket dd_full = new OSPFv2DDPacket(neighbor.summary_list)
                {
                    AreaID = smerovac.ospf.AreaID,
                    DDSequence = neighbor.dd_seq,
                    InterfaceMTU = 1500,
                    RouterID = smerovac.routerID,
                    DBDescriptionOptions = 66,
                    DBDescriptionBits = 3,
                    Checksum = 0
                };

                dd_full.Checksum = smerovac.ComputeChecksum(dd_full.HeaderData, 0, dd_full.HeaderData.Length);
                eth.PayloadPacket.PayloadPacket = dd_full;
                ((IPv4Packet)eth.PayloadPacket).UpdateIPChecksum();
                neighbor.last_s = dd_full;
                neighbor.output.port.SendPacket(eth);

                while (neighbor.last_r.DDSequence != neighbor.last_s.DDSequence)
                {
                    Thread.Sleep(100);
                    if (neighbor.state < 4) return;
                    if (--timer == 0)
                    {
                        neighbor.state = 0;
                        return;
                    }
                    if (timer % 50 == 0 && timer >= 50) neighbor.output.port.SendPacket(eth);
                }

                neighbor.summary_list.Clear();
                timer = 1000;
                OSPFv2DDPacket dd_empty = new OSPFv2DDPacket()
                {
                    AreaID = smerovac.ospf.AreaID,
                    DDSequence = neighbor.dd_seq,
                    InterfaceMTU = 1500,
                    RouterID = smerovac.routerID,
                    DBDescriptionOptions = 66,
                    DBDescriptionBits = 1,
                    Checksum = 0
                };

                dd_empty.Checksum = smerovac.ComputeChecksum(dd_empty.HeaderData, 0, dd_empty.HeaderData.Length);
                eth.PayloadPacket.PayloadPacket = dd_empty;
                ((IPv4Packet)eth.PayloadPacket).UpdateIPChecksum();
                neighbor.last_s = dd_empty;
                neighbor.output.port.SendPacket(eth);

                while (neighbor.last_r.DDSequence != neighbor.last_s.DDSequence || neighbor.state == 4)
                {
                    Thread.Sleep(100);
                    if (neighbor.state < 4) return;
                    if (--timer == 0)
                    {
                        neighbor.state = 0;
                        return;
                    }
                    if (timer % 50 == 0 && timer >= 50) neighbor.output.port.SendPacket(eth);
                }
            }
            while (neighbor.state != 5)
            {
                Thread.Sleep(50);
            }
            Loading(neighbor, eth);
        }

        public void Loading(Neighbor neighbor, EthernetPacket eth)
        {
            Console.WriteLine(neighbor.neighbor_id + " TRANSITION TO LOADING");

            List<LinkStateRequest> request_list = new List<LinkStateRequest>();
            foreach (LSA lsa in neighbor.request_list)
            {
                request_list.Add(new LinkStateRequest()
                {
                    AdvertisingRouter = lsa.AdvertisingRouter,
                    LinkStateID = lsa.LinkStateID,
                    LSType = lsa.LSType
                });
            }

            while (neighbor.GetRequestList().Count > 0)
            {
                if (neighbor.state < 5) return;
                OSPFv2LSRequestPacket request = new OSPFv2LSRequestPacket(request_list)
                {
                    AreaID = smerovac.ospf.AreaID,
                    Checksum = 0,
                    RouterID = smerovac.routerID
                };
                request.Checksum = smerovac.ComputeChecksum(request.HeaderData, 0, request.HeaderData.Length);
                eth.PayloadPacket.PayloadPacket = request;
                ((IPv4Packet)eth.PayloadPacket).UpdateIPChecksum();
                neighbor.output.port.SendPacket(eth);
                Thread.Sleep(5000);
            }

            neighbor.state = 6;
            smerovac.mut_sused.WaitOne();
            MakeRouterLSA(neighbor.output, smerovac.ospf.DRs[smerovac.ports.IndexOf(neighbor.output)]);
            if (smerovac.ospf.DRs[smerovac.ports.IndexOf(neighbor.output)].Equals(neighbor.output.ip_add))
                MakeNetworkLSA(neighbor.output, smerovac.ospf.DRs[smerovac.ports.IndexOf(neighbor.output)]);
            smerovac.mut_sused.ReleaseMutex();
            Console.WriteLine(neighbor.neighbor_id + " TRANSITION TO FULL");
            return;
        }

        public void SendRequestedLSAs(Neighbor neighbor, OSPFv2LSRequestPacket requestPacket, PhysicalAddress mac)
        {
            List<LSA> list_to_send = new List<LSA>();
            LSA lsa = null;

            smerovac.mut_database.WaitOne();
            foreach (LinkStateRequest req in requestPacket.LinkStateRequests)
            {
                lsa = smerovac.GetRequestedLSA(req);
                if (lsa == null)
                {
                    SeqNumberMismatch(neighbor);
                    smerovac.mut_database.ReleaseMutex();
                    return;
                }
                else list_to_send.Add(lsa);
            }
            smerovac.mut_database.ReleaseMutex();

            EthernetPacket eth = new EthernetPacket(neighbor.output.port.MacAddress, mac, EthernetPacketType.IPv4);
            IPv4Packet ip = new IPv4Packet(neighbor.output.ip_add, neighbor.ip_add)
            {
                TimeToLive = 1,
                Checksum = 0
            };

            OSPFv2LSUpdatePacket update = new OSPFv2LSUpdatePacket(list_to_send)
            {
                AreaID = smerovac.ospf.AreaID,
                Checksum = 0,
                RouterID = smerovac.routerID,
            };

            update.Checksum = smerovac.ComputeChecksum(update.HeaderData, 0, update.HeaderData.Length);
            eth.PayloadPacket = ip;
            ip.PayloadPacket = update;
            ip.UpdateIPChecksum();
            neighbor.output.port.SendPacket(eth);
        }

        public void SendLastSendDD(Neighbor neighbor, PhysicalAddress mac)
        {
            EthernetPacket eth = new EthernetPacket(neighbor.output.port.MacAddress, mac, EthernetPacketType.IPv4);
            IPv4Packet ip = new IPv4Packet(neighbor.output.ip_add, neighbor.ip_add)
            {
                TimeToLive = 1,
                Checksum = 0
            };

            eth.PayloadPacket = ip;
            ip.PayloadPacket = neighbor.last_s;
            ip.UpdateIPChecksum();
            neighbor.output.port.SendPacket(eth);
        }

        public LSA GetNewerLSA(LSA newLSA, LSA myLSA)
        {
            if (newLSA.LSSequenceNumber > myLSA.LSSequenceNumber)
            {
                return newLSA;
            }
            else if (newLSA.LSSequenceNumber < myLSA.LSSequenceNumber)
            {
                return myLSA;
            }
            else
            {
                if (newLSA.Checksum != myLSA.Checksum)
                {
                    if (newLSA.Checksum > myLSA.Checksum)
                    {
                        return newLSA;
                    }
                    else return myLSA;
                }
                else if ((newLSA.LSAge == 3600 && myLSA.LSAge != 3600) || (newLSA.LSAge != 3600 && myLSA.LSAge == 3600))
                {
                    return newLSA.LSAge == 3600 ? newLSA : myLSA;
                }
                else if (Math.Abs(newLSA.LSAge - myLSA.LSAge) > 900)
                {
                    return newLSA.LSAge < myLSA.LSAge ? newLSA : myLSA;
                }
                else return null;
            }
        }

        public void ProcessDBD(Neighbor neighbor, List<LSA> list)
        {
            foreach (LSA lsa in list)
            {
                if (lsa.LSType != LSAType.Network && lsa.LSType != LSAType.Router)
                {
                    SeqNumberMismatch(neighbor);
                    return;
                }
                DatabaseRecord myLSA = smerovac.GetInstanceOfLSA(lsa);
                if (myLSA == null || GetNewerLSA(lsa, myLSA.lsa) == lsa)
                {
                    neighbor.AddToRequestList(lsa);
                }
            }
        }

        public void ProcessLSU(Neighbor neighbor, List<LSA> list, Port port, IPAddress ip, PhysicalAddress mac)
        {
            Console.WriteLine(" ZACAL SOM LSU");
            foreach (LSA lsa in list)
            {
                if (!smerovac.IsChecksumCorrect(lsa.Bytes, 2, lsa.Length)) continue;
                if (lsa.LSType != LSAType.Network && lsa.LSType != LSAType.Router) continue;
                Console.WriteLine(" ZACAL SOM GETINSTANCELSA");
                DatabaseRecord myLSA = smerovac.GetInstanceOfLSA(lsa);
                Console.WriteLine("SKONCIL SOM GETINSTANCELSA------------");
                Console.WriteLine("ZACAL SOM Countofneighbor");
                int count = smerovac.CountOfNeighborInStates(4, 5);
                Console.WriteLine("SKONCIL SOM Countofneighbor-----------");
                if (lsa.LSAge == 3600 && myLSA == null && count == 0)
                {
                    Console.WriteLine("ZACAL SOM ACK 5");
                    Acknowledge(lsa, port, neighbor, 5, mac);
                    Console.WriteLine("SKONCIL SOM ACK 5---------");
                    continue;
                }
                
                if (myLSA == null || GetNewerLSA(lsa, myLSA.lsa) == lsa)
                {
                    if (myLSA != null && myLSA.learned < 1)
                    {
                        // NO ACK
                        continue;
                    }
                    Console.WriteLine("ZACAL SOM FLOOD");
                    bool flag = Flood(lsa, neighbor, port, ip);
                    Console.WriteLine("SKONCIL SOM FLOOD------");
                    smerovac.mut_sused.WaitOne();
                    foreach (Neighbor nei in smerovac.neighbors)
                    {
                        if (myLSA != null)
                        {
                            Console.WriteLine("ZACAL SOM RemoveRetrans");
                            nei.RemoveRetransLSA(myLSA.lsa);
                            Console.WriteLine("SKONCIL SOM RemoveRetrans-----");
                        }
                    }
                    smerovac.mut_sused.ReleaseMutex();
                    Console.WriteLine("ZACAL SOM INSTALL");
                    Install(lsa, myLSA);
                    Console.WriteLine("SKONCIL SOM INSTALL------");
                    if (!flag && (myLSA == null || GetNewerLSA(lsa, myLSA.lsa) == lsa))
                    {
                        Console.WriteLine("ZACAL SOM ACK 2");
                        Acknowledge(lsa, port, neighbor, 2, mac);
                        Console.WriteLine("SKONCIL SOM ACK 2-----");
                    }
                    if (lsa.AdvertisingRouter.Equals(smerovac.routerID) || (lsa.LSType == LSAType.Network && (lsa.LinkStateID.Equals(smerovac.GetPortAt(0).ip_add) || lsa.LinkStateID.Equals(smerovac.GetPortAt(1).ip_add))))
                    {
                        Console.WriteLine("ZACAL SOM SELFORIG");
                        SelfOriginated(lsa, port);
                        Console.WriteLine("SKONCIL SOM SELFORIG ---------");
                    }
                }
                else if (neighbor.IsInstanceInRequestList(lsa) != null)
                {
                    Console.WriteLine("ZACAL SOM SEQ");
                    SeqNumberMismatch(neighbor);
                    Console.WriteLine("SKONCIL SOM SEQ------");
                    return;
                }
                else if (GetNewerLSA(lsa, myLSA.lsa) == null)
                {
                    Console.WriteLine("ZACAL SOM ISINSTANCEINRETRANS");
                    bool x = neighbor.IsInstanceInRetransList(lsa);
                    Console.WriteLine("SKONCIL SOM ISINSTANCEINRETRANS--------");
                    if (x)
                    {
                        Console.WriteLine("ZACAL SOM REMOVERETRANS");
                        neighbor.RemoveRetransLSA(lsa);
                        Console.WriteLine("SKONCIL SOM REMOVERETRANS------");
                        Console.WriteLine("ZACAL SOM ACK 3");
                        Acknowledge(lsa, port, neighbor, 3, mac); // AS IMPLIED ACK
                        Console.WriteLine("SKONCIL SOM ACK 3--------");
                    }
                    else {
                        Console.WriteLine("ZACAL SOM ACK 4");
                        Acknowledge(lsa, port, neighbor, 4, mac);
                        Console.WriteLine("SKONCIL SOM ACK 4-----");
                    }
                }
                else
                {
                    if (myLSA.lsa.LSAge == 3600 && myLSA.lsa.LSSequenceNumber == 0x7fffffff)
                    {
                        continue;
                    }
                    EthernetPacket eth = new EthernetPacket(port.port.MacAddress, mac, EthernetPacketType.IPv4);
                    IPv4Packet ipp = new IPv4Packet(port.ip_add, neighbor.ip_add)
                    {
                        TimeToLive = 1,
                        Checksum = 0,
                    };
                    OSPFv2LSUpdatePacket lsu = new OSPFv2LSUpdatePacket(new List<LSA>() { myLSA.lsa })
                    {
                        AreaID = smerovac.ospf.AreaID,
                        Checksum = 0,
                        RouterID = smerovac.routerID
                    };
                    eth.PayloadPacket = ipp;
                    ipp.PayloadPacket = lsu;
                    lsu.Checksum = smerovac.ComputeChecksum(lsu.HeaderData, 0, lsu.HeaderData.Length);
                    ipp.UpdateIPChecksum();
                    port.port.SendPacket(eth);
                }
            }
            Console.WriteLine(" SKONCIL SOM LSU");
        }

        public void Acknowledge(LSA lsa, Port port, Neighbor neighbor, int flag, PhysicalAddress mac)
        {
            if (flag == 1)
            {
                //NO ACK
            }
            else if (flag == 2)
            {
                if (smerovac.ospf.BDRs.ElementAt(smerovac.ports.IndexOf(port)).Equals(port.ip_add))
                {
                    if (smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(port)).Equals(neighbor.ip_add))
                    {
                        SendDelayedACK(lsa, port, neighbor);
                    }
                }
                else SendDelayedACK(lsa, port, neighbor);
            }
            else if (flag == 3)
            {
                if (smerovac.ospf.BDRs.ElementAt(smerovac.ports.IndexOf(port)).Equals(port.ip_add))
                {
                    if (smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(port)).Equals(neighbor.ip_add))
                    {
                        SendDelayedACK(lsa, port, neighbor);
                    }
                }
            }
            else if (flag == 4)
            {
                SendDirectACK(lsa, port, neighbor, mac);
            }
            else
            {
                SendDirectACK(lsa, port, neighbor, mac);
            }
        }

        public bool Flood(LSA lsa, Neighbor neighbor, Port p, IPAddress ip)
        {
            bool added = false;
            bool receiving = false;
            foreach (Port port in smerovac.ports)
            {
                if (port.ospf)
                {
                    foreach (Neighbor nei in smerovac.neighbors)
                    {
                        if (nei.output == port)
                        {
                            if (nei.state < 4) continue;
                            else if (nei.state != 6) // Examine the link state request list of neighbor
                            {
                                LSA neighbors = nei.IsInstanceInRequestList(lsa);
                                if (neighbors != null)
                                {
                                    if (GetNewerLSA(lsa, neighbors) == neighbors)
                                    {
                                        continue;
                                    }
                                    else if (GetNewerLSA(lsa, neighbors) == null)
                                    {
                                        nei.RemoveRequestLSA(neighbors);
                                        continue;
                                    }
                                    else nei.RemoveRequestLSA(neighbors);
                                }
                            }
                            if (nei.ip_add.Equals(ip))
                            {
                                continue;
                            }
                            added = true;
                            nei.retransmission_list.Add(lsa);
                        }
                        if (!added) continue;
                        if (port == p && (smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(p)).Equals(neighbor.ip_add) || smerovac.ospf.BDRs.ElementAt(smerovac.ports.IndexOf(p)).Equals(neighbor.ip_add))) continue;
                        if (port == p && (smerovac.ospf.BDRs.ElementAt(smerovac.ports.IndexOf(port)).Equals(port.ip_add))) continue;
                        if (port == p) receiving = true;
                        SendLSU(lsa, port, nei);
                    }
                }
            }
            return receiving;
        }

        public void SendLSU(LSA lsa, Port port, Neighbor neighbor)
        {
            EthernetPacket eth = new EthernetPacket(port.port.MacAddress, PhysicalAddress.Parse("01-00-5E-00-00-05"), EthernetPacketType.IPv4);
            IPv4Packet ip;
            if (smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(port)).Equals(port.ip_add) || smerovac.ospf.BDRs.ElementAt(smerovac.ports.IndexOf(port)).Equals(port.ip_add))
            {
                ip = new IPv4Packet(port.ip_add, IPAddress.Parse("224.0.0.5"))
                {
                    TimeToLive = 1
                };
            } else ip = new IPv4Packet(port.ip_add, IPAddress.Parse("224.0.0.6"))
            {
                TimeToLive = 1
            };
            OSPFv2LSUpdatePacket updatePacket = new OSPFv2LSUpdatePacket(new List<LSA>() { lsa })
            {
                AreaID = smerovac.ospf.AreaID,
                Checksum = 0,
                RouterID = smerovac.routerID
            };
            updatePacket.Checksum = smerovac.ComputeChecksum(updatePacket.HeaderData, 0, updatePacket.HeaderData.Length);
            eth.PayloadPacket = ip;
            ip.PayloadPacket = updatePacket;
            ip.UpdateIPChecksum();
            port.port.SendPacket(eth);

            //new Thread(() => Retrans(neighbor, lsa)).Start();
        }

        public void Retrans(Neighbor neighbor, LSA lsa)
        {
            PhysicalAddress neighbor_mac = ARPLookup(neighbor.ip_add);
            while (neighbor_mac == null)
            {
                PosliArpRequest(neighbor.output, neighbor.ip_add);
                Thread.Sleep(100);
                neighbor_mac = ARPLookup(neighbor.ip_add);
            }

            EthernetPacket eth2 = new EthernetPacket(neighbor.output.port.MacAddress, neighbor_mac, EthernetPacketType.IPv4);
            IPv4Packet ip2 = new IPv4Packet(neighbor.output.ip_add, neighbor.ip_add)
            {
                TimeToLive = 1,
                Checksum = 0
            };
            OSPFv2LSUpdatePacket ret = new OSPFv2LSUpdatePacket(new List<LSA> { lsa })
            {
                AreaID = smerovac.ospf.AreaID,
                Checksum = 0,
                RouterID = smerovac.routerID
            };
            ret.Checksum = smerovac.ComputeChecksum(ret.HeaderData, 0, ret.HeaderData.Length);
            eth2.PayloadPacket = ip2;
            ip2.PayloadPacket = ret;
            ip2.UpdateIPChecksum();

            int timer = 1000;
            while (neighbor.IsInstanceInRetransList(lsa))
            {
                Thread.Sleep(100);
                if (neighbor.state < 4) return;
                if (--timer == 0)
                {
                    neighbor.state = 0;
                    return;
                }
                if (timer % 50 == 0 && timer >= 50) neighbor.output.port.SendPacket(eth2);
            }
        }

        public void SPF(List<DatabaseRecord> database)
        {
            //present routing table is invalidated, is saved
            List<RT_zaznam> old = new List<RT_zaznam>();
            foreach (RT_zaznam rt in smerovac.smerovacia_tabulka)
            {
                if (rt.type == 'O')
                {
                    old.Add(rt);
                }
            }
            foreach (RT_zaznam rt in old)
            {
                smerovac.smerovacia_tabulka.Remove(rt);
            }

            //at first routers and transit network

            List<Vertex> tree = new List<Vertex>();
            List<Vertex> candidates = new List<Vertex>();
            Vertex root = new Vertex(smerovac.routerID, smerovac.my_lsa, 0, null);
            tree.Add(root);

            candidates = GetCandidates(candidates, tree, smerovac.my_lsa, root, database, 0);
            Vertex v;
            while (candidates.Count > 0)
            {
                v = getMinVertex(candidates);
                tree.Add(v);
                candidates = removeFromCandidates(candidates, v);
                candidates = GetCandidates(candidates, tree, v.lsa, v, database, v.distance);
            }
            foreach(Vertex ver in tree)
            {
                if (ver.lsa.LSType == LSAType.Router)
                {
                    foreach(RouterLink link in ((RouterLSA)ver.lsa).RouterLinks)
                    {
                        if (link.Type == 3)
                        {
                            IPAddress nexthop = null;
                            Port port = null;
                            Vertex aktual = ver, predosly = ver;
                            while (!aktual.vertex_id.Equals(smerovac.routerID))
                            {
                                if (aktual.lsa.LSType == LSAType.Router) predosly = aktual;
                                aktual = aktual.reverse;
                            }
                            if (predosly.lsa.LSType == LSAType.Network) continue;
                            foreach (RouterLink l in ((RouterLSA)predosly.lsa).RouterLinks)
                            {
                                if (IPtoNet(l.LinkData, smerovac.ports[0].maska).Equals(IPtoNet(smerovac.ports[0].ip_add, smerovac.ports[0].maska)))
                                {
                                    nexthop = l.LinkData;
                                    port = smerovac.ports[0];
                                }
                                else if (IPtoNet(l.LinkData, smerovac.ports[1].maska).Equals(IPtoNet(smerovac.ports[1].ip_add, smerovac.ports[1].maska)))
                                {
                                    nexthop = l.LinkData;
                                    port = smerovac.ports[1];
                                }
                            }
                            RT_zaznam novy = new RT_zaznam(IPtoNet(link.LinkID, link.LinkData), link.LinkData, nexthop, port, 'O');
                            novy.metric = ver.distance + link.Metric;
                            PridajSietDoTabulky(novy);
                        }
                    }
                }
                else
                {
                    NetworkLSA network = (NetworkLSA)ver.lsa;
                    //Vypocitat nexthop
                    IPAddress nexthop = null;
                    Port port = null;
                    Vertex aktual = ver, predosly = ver;
                    while (!aktual.vertex_id.Equals(smerovac.routerID))
                    {
                        if (aktual.lsa.LSType == LSAType.Router) predosly = aktual;
                        aktual = aktual.reverse;
                    }
                    if (predosly.lsa.LSType == LSAType.Network) continue;
                    foreach(RouterLink link in ((RouterLSA)predosly.lsa).RouterLinks)
                    {
                        if (IPtoNet(link.LinkData, smerovac.ports[0].maska).Equals(IPtoNet(smerovac.ports[0].ip_add, smerovac.ports[0].maska)))
                        {
                            nexthop = link.LinkData;
                            port = smerovac.ports[0];
                        } else if (IPtoNet(link.LinkData, smerovac.ports[1].maska).Equals(IPtoNet(smerovac.ports[1].ip_add, smerovac.ports[1].maska)))
                        {
                            nexthop = link.LinkData;
                            port = smerovac.ports[1];
                        }
                    }
                    RT_zaznam novy = new RT_zaznam(IPtoNet(network.LinkStateID, network.NetworkMask), network.NetworkMask, nexthop, port, 'O');
                    novy.metric = ver.distance;
                    PridajSietDoTabulky(novy);
                }
            }
        }

        public List<Vertex> removeFromCandidates(List<Vertex> list, Vertex vertex)
        {
            List<Vertex> to_delete = new List<Vertex>();
            foreach(Vertex v in list)
            {
                if (v.vertex_id.Equals(vertex.vertex_id)) to_delete.Add(v);
            }
            foreach(Vertex v in to_delete)
            {
                list.Remove(v);
            }
            return list;
        }

        public Vertex getMinVertex(List<Vertex> list)
        {
            Vertex min = null;
            foreach (Vertex vertex in list)
            {
                if (min == null) min = vertex;
                else if (min.distance > vertex.distance) min = vertex;
            }
            return min;
        }

        public RouterLSA getRLSA(List<DatabaseRecord> database, IPAddress ip)
        {
            foreach(DatabaseRecord lsa in database)
            {
                if (lsa.lsa.LSType == LSAType.Router && ip.Equals(lsa.lsa.LinkStateID))
                {
                    if (lsa.lsa.LSAge < 3600) return (RouterLSA)lsa.lsa;
                    else return null;
                }
            }
            return null;
        }

        public NetworkLSA getNetwork(List<DatabaseRecord> database, IPAddress ip)
        {
            foreach (DatabaseRecord lsa in database)
            {
                if (lsa.lsa.LSType == LSAType.Network && ip.Equals(lsa.lsa.LinkStateID))
                {
                    if (lsa.lsa.LSAge < 3600) return (NetworkLSA)lsa.lsa;
                    else return null;
                }
            }
            return null;
        }

        public bool IsInTree(LSA lsa, List<Vertex> tree)
        {
            foreach(Vertex vertex in tree)
            {
                // MOZNO NEBUDE FUNGOVAT
                if (lsa.LinkStateID.Equals(vertex.vertex_id) && lsa == vertex.lsa)
                    return true;
            }
            return false;
        }

        public List<Vertex> GetCandidates(List<Vertex> candidates, List<Vertex> tree, LSA lsa, Vertex vertex, List<DatabaseRecord> database, int cost)
        {
            if (lsa.LSType == LSAType.Router)
            {
                foreach (RouterLink link in ((RouterLSA)(lsa)).RouterLinks)
                {
                    if (link.Type == 3)
                    {
                        continue;
                    }
                    else if (link.Type == 2)
                    {
                        NetworkLSA net = getNetwork(database, link.LinkID);
                        if (net != null && !IsInTree(net, tree))
                        {
                            Vertex newvertex = new Vertex(net.LinkStateID, net, cost + link.Metric, vertex);
                            candidates.Add(newvertex);
                        }
                    }
                    else
                    {
                        RouterLSA router = getRLSA(database, link.LinkID);
                        if (router != null && !IsInTree(router, tree))
                        {
                            Vertex newvertex = new Vertex(router.LinkStateID, router, cost + link.Metric, vertex);
                            candidates.Add(newvertex);
                        }
                    }
                }
            } else
            {
                foreach(IPAddress ip in ((NetworkLSA)lsa).AttachedRouters)
                {
                    RouterLSA router = getRLSA(database, ip);
                    if (router != null && !IsInTree(router, tree))
                    {
                        Vertex newvertex = new Vertex(router.LinkStateID, router, cost, vertex);
                        candidates.Add(newvertex);
                    }
                }
            }
            return candidates;
        }

        public void Install(LSA lsa, DatabaseRecord old)
        {
            smerovac.mut_database.WaitOne();
            if (old != null) smerovac.my_database.Remove(old);
            smerovac.my_database.Add(new DatabaseRecord(lsa));
            List<DatabaseRecord> copy = smerovac.my_database;
            smerovac.mut_database.ReleaseMutex();
            foreach (Neighbor nei in smerovac.neighbors)
            {
                if (old != null) nei.RemoveRetransLSA(old.lsa);
            }
            
            //SPF
            new Thread(() =>
            {
                smerovac.mut_spf.WaitOne();
                SPF(copy);
                smerovac.mut_spf.ReleaseMutex();
            }).Start();
        }

        public void SelfOriginated(LSA lsa, Port port)
        {
            Console.WriteLine("SELF ORIGINATED LSA");
            if (lsa.LSType == LSAType.Network && smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(port)).Equals(port.ip_add))
            {
                NetworkLSA net = null;
                smerovac.mut_sused.WaitOne();
                List<IPAddress> routers = FullNeighbor(port);
                smerovac.mut_sused.ReleaseMutex();
                if (routers.Count == 0) return;
                routers.Add(smerovac.routerID);
                NetworkLSA newnet = new NetworkLSA(routers)
                {
                    Options = 2,
                    LSAge = 0,
                    LinkStateID = smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(port)),
                    AdvertisingRouter = smerovac.routerID,
                    LSSequenceNumber = lsa.LSSequenceNumber + 1,
                    Checksum = 0,
                    NetworkMask = port.maska
                };

                if (smerovac.my_network_lsa.Count > 0)
                {
                    foreach (NetworkLSA n in smerovac.my_network_lsa)
                        if (n.LinkStateID.Equals(port.ip_add)) net = n;
                }

                if (net != null)
                {
                    smerovac.my_network_lsa.Remove(net);
                }
                newnet.Checksum = smerovac.Fletcher(newnet.Bytes, 2, newnet.Length);
                smerovac.my_network_lsa.Add(newnet);
                Flood(newnet, null, null, null);
                DatabaseRecord old = smerovac.GetInstanceOfLSA(net);
                Install(newnet, old);
            }
            else if (LSAType.Network == lsa.LSType)
            {
                lsa.LSAge = 3600;
                Flood(lsa, null, null, null);
            } else if (LSAType.Router == lsa.LSType)
            {
                if (GetNewerLSA(lsa, smerovac.my_lsa) == lsa)
                {
                    RouterLSA mynew = new RouterLSA(smerovac.links)
                    {
                        Options = 2,
                        LSAge = 0,
                        LinkStateID = smerovac.routerID,
                        AdvertisingRouter = smerovac.routerID,
                        LSSequenceNumber = lsa.LSSequenceNumber + 1,
                        Checksum = 0,
                        VBit = 0,
                        EBit = 0,
                        BBit = 0
                    };
                    mynew.Checksum = smerovac.Fletcher(mynew.Bytes, 2, mynew.Length);
                    smerovac.my_lsa = mynew;
                    Flood(mynew, null, null, null);
                    DatabaseRecord old = smerovac.GetInstanceOfLSA(lsa);
                    Install(mynew, old);
                }
            }
        }

        public void SendDelayedACK(LSA lsa, Port port, Neighbor neighbor)
        {
            EthernetPacket eth = new EthernetPacket(port.port.MacAddress, PhysicalAddress.Parse("01-00-5E-00-00-05"), EthernetPacketType.IPv4);
            IPv4Packet ip;
            if (smerovac.ospf.BDRs.ElementAt(smerovac.ports.IndexOf(port)).Equals(port.ip_add) || smerovac.ospf.DRs.ElementAt(smerovac.ports.IndexOf(port)).Equals(port.ip_add))
            {
                ip = new IPv4Packet(port.ip_add, IPAddress.Parse("224.0.0.5"))
                {
                    TimeToLive = 1
                };
            }
            else
            {
                ip = new IPv4Packet(port.ip_add, IPAddress.Parse("224.0.0.6"))
                {
                    TimeToLive = 1
                };
            }
            OSPFv2LSAPacket ack = new OSPFv2LSAPacket(new List<LSA>() { lsa })
            {
                AreaID = smerovac.ospf.AreaID,
                Checksum = 0,
                RouterID = smerovac.routerID
            };

            eth.PayloadPacket = ip;
            ip.PayloadPacket = ack;
            ack.Checksum = smerovac.ComputeChecksum(ack.HeaderData, 0, ack.HeaderData.Length);
            ip.UpdateIPChecksum();
            port.port.SendPacket(eth);
        }

        public void SendDirectACK(LSA lsa, Port port, Neighbor neighbor, PhysicalAddress mac)
        {
            Console.WriteLine("ZACAL SOM SENDDIRECKACK");
            
            EthernetPacket eth = new EthernetPacket(port.port.MacAddress, mac, EthernetPacketType.IPv4);
            IPv4Packet ip = new IPv4Packet(port.ip_add, neighbor.ip_add)
            {
                TimeToLive = 1,
                Checksum = 0
            };
            OSPFv2LSAPacket ack = new OSPFv2LSAPacket(new List<LSA>() { lsa })
            {
                AreaID = smerovac.ospf.AreaID,
                Checksum = 0,
                RouterID = smerovac.routerID
            };

            eth.PayloadPacket = ip;
            ip.PayloadPacket = ack;
            ack.Checksum = smerovac.ComputeChecksum(ack.HeaderData, 0, ack.HeaderData.Length);
            ip.UpdateIPChecksum();
            neighbor.output.port.SendPacket(eth);
            Console.WriteLine("SKONCIL SOM SENDDIRECKACK--------");
        }

        /*
         * ================================================================
         *          ROUTER
         * ================================================================
         */

        public void NastavIpPortu1(object sender, RoutedEventArgs e)
        {
            if (Port1_ip_text.Text != "")
            {
                smerovac.GetPortAt(0).SetIP(Port1_ip_text.Text);
                if (smerovac.GetPortAt(0).maska != null)
                    NastavConnectedSiet(smerovac.GetPortAt(0));
                if (smerovac.manualne_RID == false)
                    RouterID.Content = smerovac.VyberRID();
                Port1_ip.Content = Port1_ip_text.Text;
                Port1_ip_text.Text = "";
            }
        }

        public void NastavIpPortu2(object sender, RoutedEventArgs e)
        {
            if (Port2_ip_text.Text != "")
            {                
                smerovac.GetPortAt(1).SetIP(Port2_ip_text.Text);
                if (smerovac.GetPortAt(1).maska != null)
                    NastavConnectedSiet(smerovac.GetPortAt(1));
                if (smerovac.manualne_RID == false)
                    RouterID.Content = smerovac.VyberRID();
                Port2_ip.Content = Port2_ip_text.Text;
                Port2_ip_text.Text = "";
            }
        }

        public void NastavMaskuPortu1(object sender, RoutedEventArgs e)
        {
            if (Port1_mask_text.Text != "")
            {                
                smerovac.GetPortAt(0).SetMask(Port1_mask_text.Text);
                if (smerovac.GetPortAt(0).ip_add != null)
                    NastavConnectedSiet(smerovac.GetPortAt(0));
                Port1_mask.Content = Port1_mask_text.Text;
                Port1_mask_text.Text = "";
            }
        }

        public void NastavMaskuPortu2(object sender, RoutedEventArgs e)
        {
            if (Port2_mask_text.Text != "")
            {
                smerovac.GetPortAt(1).SetMask(Port2_mask_text.Text);
                if (smerovac.GetPortAt(1).ip_add != null)
                    NastavConnectedSiet(smerovac.GetPortAt(1));
                Port2_mask.Content = Port2_mask_text.Text;
                Port2_mask_text.Text = "";
            }
        }

        public void NastavRouterID(object sender, RoutedEventArgs e)
        {
            if (RouterID_text.Text != "")
            {
                RouterID.Content = RouterID_text.Text;
                smerovac.manualne_RID = true;
                smerovac.SetRouterID(RouterID_text.Text);
                RouterID_text.Text = "";
            }
        }

        public void NastavCostPortu1(object sender, RoutedEventArgs e)
        {
            if (CostPort1.Text != "")
            {
                smerovac.ports[0].cost = int.Parse(CostPort1.Text);
                if (smerovac.GetPortAt(0).ospf) {
                    smerovac.mut_sused.WaitOne();
                    MakeRouterLSA(smerovac.GetPortAt(0), smerovac.ospf.DRs[smerovac.ports.IndexOf(smerovac.GetPortAt(0))]);
                    smerovac.mut_sused.ReleaseMutex();
                }
            }
            CostPort1.Text = "";
        }

        public void NastavCostPortu2(object sender, RoutedEventArgs e)
        {
            if (CostPort2.Text != "")
            {
                smerovac.ports[1].cost = int.Parse(CostPort2.Text);
                if (smerovac.GetPortAt(1).ospf)
                {
                    smerovac.mut_sused.WaitOne();
                    MakeRouterLSA(smerovac.GetPortAt(1), smerovac.ospf.DRs[smerovac.ports.IndexOf(smerovac.GetPortAt(1))]);
                    smerovac.mut_sused.ReleaseMutex();
                }
            }
            CostPort2.Text = "";
        }

        public void OtvorPorty()
        {
            smerovac.ports[0].port.OnPacketArrival += new PacketArrivalEventHandler(PacketArrival);
            smerovac.ports[1].port.OnPacketArrival += new PacketArrivalEventHandler(PacketArrival);
            smerovac.ports[0].port.Open(OpenFlags.Promiscuous | OpenFlags.NoCaptureLocal, 10);
            smerovac.ports[1].port.Open(OpenFlags.Promiscuous | OpenFlags.NoCaptureLocal, 10);
            smerovac.ports[0].port.StartCapture();
            smerovac.ports[1].port.StartCapture();
        }

        /*
         * ================================================================
         *          ROUTING TABLE
         * ================================================================
         */
        
        public bool ViemSmerovatDoSiete(IPAddress ip, Port port)
        {
            Tuple<IPAddress, Port> ret = IPLookup(ip, ip);
            if (ret == null || ret.Item2 == port)
                return false;
            else return true;
        }

        public Tuple<IPAddress, Port> IPLookup(IPAddress ip, IPAddress original)
        {
            RT_zaznam best_zaznam = null;

            smerovac.mut_rt.WaitOne();
            foreach (RT_zaznam rt in smerovac.smerovacia_tabulka)
                if (IPtoNet(ip, rt.maska).Equals(rt.ip_add) && ((best_zaznam == null) || (best_zaznam.cidr_mask < rt.cidr_mask) || 
                    (best_zaznam.cidr_mask == rt.cidr_mask && best_zaznam.metric > rt.metric)))
                    best_zaznam = rt;

            smerovac.mut_rt.ReleaseMutex();
            if (best_zaznam == null) return null;

            if (best_zaznam.output != null)
                if (best_zaznam.next_hop != null)
                    return Tuple.Create(best_zaznam.next_hop, best_zaznam.output);
                else
                {
                    if (best_zaznam.type == 'C') return Tuple.Create(ip, best_zaznam.output);
                    else return Tuple.Create(original, best_zaznam.output);
                }
            else if (best_zaznam.next_hop != null)
                return IPLookup(best_zaznam.next_hop, original);
            else return null;
        }

        public void NastavConnectedSiet(Port port)
        {
            smerovac.mut_rt.WaitOne();
            for (int i = 0; i < smerovac.smerovacia_tabulka.Count; i++)
                if (smerovac.smerovacia_tabulka.ElementAt(i).type == 'C' && smerovac.smerovacia_tabulka.ElementAt(i).output == port)
                {
                    smerovac.smerovacia_tabulka.ElementAt(i).ip_add = IPtoNet(port.ip_add, port.maska);
                    smerovac.smerovacia_tabulka.ElementAt(i).SetCIDR(port.maska);
                    VypisSmerovacejTabulky();
                    smerovac.mut_rt.ReleaseMutex();
                    return;
                }
            smerovac.mut_rt.ReleaseMutex();
            PridajSietDoTabulky(new RT_zaznam(IPtoNet(port.ip_add, port.maska), port.maska, null, port, 'C'));            
        }

        public void VymazStatickuCestu(object sender, RoutedEventArgs e)
        {
            smerovac.mut_rt.WaitOne();
            if (RTListbox.SelectedIndex != -1 && smerovac.smerovacia_tabulka.ElementAt(RTListbox.SelectedIndex).type == 'S')
                smerovac.smerovacia_tabulka.RemoveAt(RTListbox.SelectedIndex);
            VypisSmerovacejTabulky();
            smerovac.mut_rt.ReleaseMutex();
        }

        public void PridajStatickuCestu(object sender, RoutedEventArgs e)
        {
            if (StaticRouteMaskText.Text == "" || StaticRouteIpText.Text == "")
                return;
            else if (StaticRouteNextHopText.Text == "" && (StaticRoutePort.SelectedIndex == -1 || StaticRoutePort.SelectedIndex == 2))
                return;
            else if (StaticRouteNextHopText.Text == "" && StaticRoutePort.SelectedIndex < 2 && StaticRoutePort.SelectedIndex > -1)
                PridajSietDoTabulky(new RT_zaznam(IPAddress.Parse(StaticRouteIpText.Text), IPAddress.Parse(StaticRouteMaskText.Text), null, smerovac.ports.ElementAt(StaticRoutePort.SelectedIndex), 'S'));
            else if (StaticRouteNextHopText.Text != "" && StaticRoutePort.SelectedIndex == 2)
                PridajSietDoTabulky(new RT_zaznam(IPAddress.Parse(StaticRouteIpText.Text), IPAddress.Parse(StaticRouteMaskText.Text), IPAddress.Parse(StaticRouteNextHopText.Text), null, 'S'));
            else if (StaticRouteNextHopText.Text != "" && StaticRoutePort.SelectedIndex < 2 && StaticRoutePort.SelectedIndex > -1)
                PridajSietDoTabulky(new RT_zaznam(IPAddress.Parse(StaticRouteIpText.Text), IPAddress.Parse(StaticRouteMaskText.Text), IPAddress.Parse(StaticRouteNextHopText.Text), smerovac.ports.ElementAt(StaticRoutePort.SelectedIndex), 'S'));
            StaticRouteNextHopText.Text = StaticRouteIpText.Text = StaticRouteMaskText.Text = "";
            StaticRoutePort.SelectedIndex = -1;
        }

        public void PridajSietDoTabulky(RT_zaznam novy)
        {
            smerovac.mut_rt.WaitOne();
            foreach (RT_zaznam rt in smerovac.smerovacia_tabulka)
            {
                if (rt.ip_add.Equals(novy.ip_add) && rt.maska.Equals(novy.maska) && rt.metric < novy.metric)
                {
                    smerovac.mut_rt.ReleaseMutex();
                    return;
                }
            }
            smerovac.smerovacia_tabulka.Add(novy);
            VypisSmerovacejTabulky();
            smerovac.mut_rt.ReleaseMutex();
        }

        public void VypisSmerovacejTabulky()
        {
            RTListbox.Dispatcher.Invoke(() =>
            {
                RTListbox.Items.Clear();
            });
            
            foreach (RT_zaznam rt in smerovac.smerovacia_tabulka)
                RTListbox.Dispatcher.Invoke(() =>
                {
                    RTListbox.Items.Add(rt.Vypis());
                });
        }

        /*
         * ================================================================
         *          ARP
         * ================================================================
         */

        public void PosliArpRequest(Port port, IPAddress requested_ip)
        {
            EthernetPacket ethernet = new EthernetPacket(port.port.MacAddress, PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), EthernetPacketType.Arp)
            {
                PayloadPacket = new ARPPacket(ARPOperation.Request, PhysicalAddress.Parse("00-00-00-00-00-00"), requested_ip, port.port.MacAddress, port.ip_add)
            };
            port.port.SendPacket(ethernet);
        }

        public void PosliArpReply(Port port, IPAddress my_ip, PhysicalAddress my_mac, IPAddress sender_ip, PhysicalAddress sender_mac)
        {
            EthernetPacket ethernet = new EthernetPacket(port.port.MacAddress, sender_mac, EthernetPacketType.Arp)
            {
                PayloadPacket = new ARPPacket(ARPOperation.Response, sender_mac, sender_ip, my_mac, my_ip)
            };
            port.port.SendPacket(ethernet);
        }

        public void ArpRequest(object sender, RoutedEventArgs e)
        {
            if (ArpRequestIP.Text != "")
            {
                IPAddress requested_ip = IPAddress.Parse(ArpRequestIP.Text);
                foreach (Port p in smerovac.ports)
                {
                    if (p.ip_add == null || p.maska == null)
                        continue;
                    if (IPtoNet(p.ip_add, p.maska).Equals(IPtoNet(requested_ip, p.maska)) && requested_ip != p.ip_add)
                    {
                        PosliArpRequest(p, requested_ip);
                        break;
                    }
                }
            }
            ArpRequestIP.Text = "";
        }

        public void VymazArp(object sender, RoutedEventArgs e)
        {
            smerovac.mut_arp.WaitOne();
            smerovac.arp_tabulka.Clear();
            ArpListbox.Items.Clear();
            smerovac.mut_arp.ReleaseMutex();
        }

        public void NastavArpCasovac(object sender, RoutedEventArgs e)
        {
            if (ArpTimer.Text != "")
                smerovac.arp_timer = int.Parse(ArpTimer.Text);
            ArpTimer.Text = "";
        }

        public void PridajArpZaznam(IPAddress ip, PhysicalAddress mac)
        {
            smerovac.mut_arp.WaitOne();
            foreach(ARP_zaznam arp in smerovac.arp_tabulka)
            {
                if (arp.ip_add.Equals(ip) && arp.mac_add.Equals(mac))
                {
                    arp.timer = smerovac.arp_timer;
                    smerovac.mut_arp.ReleaseMutex();
                    return;
                }
            }
            smerovac.arp_tabulka.Add(new ARP_zaznam(ip, mac, smerovac.arp_timer));
            smerovac.mut_arp.ReleaseMutex();
        }

        public PhysicalAddress ARPLookup(IPAddress ip)
        {
            smerovac.mut_arp.WaitOne();
            foreach (ARP_zaznam arp in smerovac.arp_tabulka)
                if (arp.ip_add.Equals(ip))
                {
                    smerovac.mut_arp.ReleaseMutex();
                    return arp.mac_add;
                }
            smerovac.mut_arp.ReleaseMutex();
            return null;
        }

        public void VypisArpTabulky()
        {
            List<ARP_zaznam> vymazat = new List<ARP_zaznam>();
            while (!stop)
            {
                smerovac.mut_arp.WaitOne();                
                ArpListbox.Dispatcher.Invoke(() =>
                {
                    ArpListbox.Items.Clear();
                });

                foreach (ARP_zaznam arp in smerovac.arp_tabulka)
                    if (--arp.timer == 0)
                        vymazat.Add(arp);
                    else ArpListbox.Dispatcher.Invoke(() =>
                    {
                        ArpListbox.Items.Add(arp.Vypis());
                    });

                foreach (ARP_zaznam arp in vymazat)
                    smerovac.arp_tabulka.Remove(arp);

                vymazat.Clear();
                smerovac.mut_arp.ReleaseMutex();
                Thread.Sleep(1000);
            }
        }
    }
}