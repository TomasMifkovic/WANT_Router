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

        public void AddToRequestList(LSA lsa)
        {
            mutex.WaitOne();
            request_list.Add(lsa);
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
                if (l.LSType == lsa.LSType && l.AdvertisingRouter == lsa.AdvertisingRouter && l.LinkStateID == lsa.LinkStateID)
                {
                    delete = l;
                    break;
                }
            }
            if (delete != null) retransmission_list.Remove(delete);
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
        public Mutex mut_arp, mut_rt, mut_sused, mut_database;
        public int arp_timer;
        public bool manualne_RID, neighbors_changed, lsa_changed;
        public List<LSA> my_database;
        public RouterLSA my_lsa = null;
        public List<NetworkLSA> my_network_lsa = null;
        public List<RouterLink> links;

        public Smerovac(WinPcapDevice rozhranie1, WinPcapDevice rozhranie2)
        {
            ports = new List<Port>
            {
                new Port(rozhranie1),
                new Port(rozhranie2)
            };

            manualne_RID = false;
            neighbors = new List<Neighbor>();
            arp_tabulka = new List<ARP_zaznam>();
            smerovacia_tabulka = new List<RT_zaznam>();
            my_database = new List<LSA>();
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

        public bool CheckRecentLSA(LSA lsa)
        {
            bool ret = true;
            mut_database.WaitOne();
            foreach (LSA l in my_database)
            {
                if (l.LSType == lsa.LSType && l.AdvertisingRouter == lsa.AdvertisingRouter && l.LinkStateID == lsa.LinkStateID)
                {
                    if ((int)l.LSSequenceNumber < (int)lsa.LSSequenceNumber)
                    {
                        ret = true;
                        break;
                    }
                        
                    if ((int)l.LSSequenceNumber == (int)lsa.LSSequenceNumber)
                    {
                        if (l.Checksum < lsa.Checksum)
                        {
                            ret = true;
                            break;
                        }
                        else if (lsa.LSAge == 3600 && l.LSAge != 3600)
                        {
                            ret = true;
                            break;
                        }
                        else if (lsa.LSAge != 3600 && l.LSAge == 3600)
                        {
                            ret = false;
                            break;
                        }
                        else if ((lsa.LSAge - l.LSAge > 900 || l.LSAge - lsa.LSAge > 900) && l.LSAge > lsa.LSAge)
                        {
                            ret = true;
                            break;
                        }
                        else {
                            ret = false;
                            break;
                        }
                    }
                }
            }
            mut_database.ReleaseMutex();
            return ret;
        }

        public LSA GetRequestedLSA(LinkStateRequest lsa)
        {
            foreach(LSA l in my_database)
            {
                if (lsa.LSType == l.LSType && lsa.AdvertisingRouter.Equals(l.AdvertisingRouter) && lsa.LinkStateID.Equals(l.LinkStateID))
                {
                    return l;
                }
            }
            return null;
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
            Console.WriteLine(x + " - " + y);
            return (ushort)((x << 8) | y);
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
                        if (ospf_packet.Type == OSPFPacketType.Hello)
                        {
                            OSPFv2HelloPacket hello = (OSPFv2HelloPacket)ospf_packet;
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
                                        MakeElection(captured);
                                        smerovac.mut_sused.ReleaseMutex();
                                    }
                                }
                            }
                        }
                        else if (ospf_packet.Type == OSPFPacketType.DatabaseDescription && ip_packet.DestinationAddress.Equals(captured.ip_add))
                        {
                            OSPFv2DDPacket dd = (OSPFv2DDPacket)ospf_packet;
                            Neighbor neighbor = GetNeighbor(ospf_packet.RouterID, ip_packet.SourceAddress);
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
                                        foreach (LSA lsa in dd.LSAHeader)
                                        {
                                            if (lsa.LSType != LSAType.Network && lsa.LSType != LSAType.Router)
                                            {
                                                SeqNumberMismatch(neighbor);
                                                return;
                                            }
                                            if (smerovac.CheckRecentLSA(lsa))
                                            {
                                                neighbor.AddToRequestList(lsa);
                                            }
                                        }
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
                                        foreach (LSA lsa in dd.LSAHeader)
                                        {
                                            if (lsa.LSType != LSAType.Network && lsa.LSType != LSAType.Router)
                                            {
                                                SeqNumberMismatch(neighbor);
                                                return;
                                            }
                                            if (smerovac.CheckRecentLSA(lsa))
                                            {
                                                neighbor.AddToRequestList(lsa);
                                            }
                                        }
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
                                            MakeRouterLSA(captured, smerovac.ospf.DRs[smerovac.ports.IndexOf(captured)]);
                                            if (smerovac.ospf.DRs[smerovac.ports.IndexOf(captured)].Equals(captured.ip_add))
                                                MakeNetworkLSA(captured, smerovac.ospf.DRs[smerovac.ports.IndexOf(captured)]);
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
                            OSPFv2LSRequestPacket request = (OSPFv2LSRequestPacket)ospf_packet;
                            Neighbor neighbor = GetNeighbor(ospf_packet.RouterID, ip_packet.SourceAddress);

                            if (neighbor.state < 4) return;

                            SendRequestedLSAs(neighbor, request, eth_packet.SourceHwAddress);
                        }
                        else if (ospf_packet.Type == OSPFPacketType.LinkStateUpdate)
                        {
                            //TODO Flooding procedure + acknowledgments
                        }
                        else if (ospf_packet.Type == OSPFPacketType.LinkStateAcknowledgment)
                        {
                            OSPFv2LSAPacket ack = (OSPFv2LSAPacket)ospf_packet;
                            Neighbor neighbor = GetNeighbor(ospf_packet.RouterID, ip_packet.SourceAddress);

                            if (neighbor.state < 4) return;

                            foreach(LSA lsa in ack.LSAAcknowledge)
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
                smerovac.my_database.Remove(net);
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
            smerovac.my_database.Add(net);

            smerovac.mut_database.ReleaseMutex();
        }

        public void FlushNetworkLSA(Port port)
        {
            //smerovac.mut_database.WaitOne();
            //NetworkLSA net = null;
            //if (smerovac.my_network_lsa.Count > 0)
            //{
            //    foreach (NetworkLSA n in smerovac.my_network_lsa)
            //        if (n.LinkStateID.Equals(port.ip_add)) net = n;
            //}
            //if (net != null)
            //{
            //    smerovac.my_network_lsa.Remove(net);
            //    smerovac.my_database.Remove(net);
            //}
            //smerovac.mut_database.ReleaseMutex();
        }

        public void MakeRouterLSA(Port port, IPAddress dr)
        {
            smerovac.mut_database.WaitOne();
            if (dr.Equals(IPAddress.Parse("0.0.0.0"))) MakeStub(port);
            else if ((!port.ip_add.Equals(dr) && (GetNeighbor(null, dr).state == 6)) || (port.ip_add.Equals(dr) && FullNeighbor(port).Count > 0)) MakeTransit(port, dr);
            else MakeStub(port);
            smerovac.mut_database.ReleaseMutex();
        }

        public void MakeStub(Port port)
        {
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
            }
            else need_new = true;

            if (need_new)
            {
                smerovac.links.Add(new RouterLink()
                {
                    LinkID = IPtoNet(port.ip_add, port.maska),
                    LinkData = port.maska,
                    Type = 3,
                    Metric = (ushort)port.cost
                });

                uint old_seq = 0x80000000;
                if (smerovac.my_lsa != null)
                {
                    old_seq = smerovac.my_lsa.LSSequenceNumber;
                    smerovac.my_database.Remove(smerovac.my_lsa);
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

                //smerovac.my_lsa.Checksum = smerovac.ComputeChecksum(smerovac.my_lsa.Bytes, 2, smerovac.my_lsa.Bytes.Length - 2);
                smerovac.my_lsa.Checksum = smerovac.Fletcher(smerovac.my_lsa.Bytes, 2, smerovac.my_lsa.Length);
                smerovac.my_database.Add(smerovac.my_lsa);
            }
        }

        public void MakeTransit(Port port, IPAddress dr)
        {
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
            }
            else need_new = true;

            if (need_new)
            {
                smerovac.links.Add(new RouterLink()
                {
                    LinkID = dr,
                    LinkData = port.ip_add,
                    Type = 2,
                    Metric = (ushort)port.cost
                });

                uint old_seq = 0x80000000;
                if (smerovac.my_lsa != null)
                {
                    old_seq = smerovac.my_lsa.LSSequenceNumber;
                    smerovac.my_database.Remove(smerovac.my_lsa);
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
                smerovac.my_database.Add(smerovac.my_lsa);
            }
        }

        public void IncrementLsaAge()
        {
            List<LSA> vymazat = new List<LSA>();
            while (!stop)
            {
                vymazat.Clear();
                
                smerovac.mut_database.WaitOne();
                DatabaseListbox.Dispatcher.Invoke(() =>
                {
                    DatabaseListbox.Items.Clear();
                });
                foreach (LSA lsa in smerovac.my_database)
                {
                    if (++lsa.LSAge == 3600)
                    {
                        vymazat.Add(lsa);
                    }
                    else
                    {
                        DatabaseListbox.Dispatcher.Invoke(() =>
                        {
                            DatabaseListbox.Items.Add(lsa.LSAge + "\t" + lsa.LSType + "\t" + lsa.LinkStateID + "\t" + lsa.AdvertisingRouter + "\t" + lsa.LSSequenceNumber);
                        });
                    }
                }
                foreach (LSA lsa in vymazat)
                    smerovac.my_database.Remove(lsa);

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
                MakeRouterLSA(smerovac.GetPortAt(0), smerovac.ospf.DRs[smerovac.ports.IndexOf(smerovac.GetPortAt(0))]);
                th_hello1.Start();
                th_waitTimer1.Start();
                OspfButt1.Content = "Vypnúť OSPF na porte 1";
            } else
            {
                smerovac.GetPortAt(0).ospf = false;
                MakeRouterLSA(smerovac.GetPortAt(0), smerovac.ospf.DRs[smerovac.ports.IndexOf(smerovac.GetPortAt(0))]);
                th_hello1.Join();
                th_hello1 = null;
                th_waitTimer1.Join();
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
                MakeRouterLSA(smerovac.GetPortAt(1), smerovac.ospf.DRs[smerovac.ports.IndexOf(smerovac.GetPortAt(1))]);
                th_hello2.Start();
                th_waitTimer1.Start();
                OspfButt2.Content = "Vypnúť OSPF na porte 2";
            }
            else
            {
                smerovac.GetPortAt(1).ospf = false;
                MakeRouterLSA(smerovac.GetPortAt(1), smerovac.ospf.DRs[smerovac.ports.IndexOf(smerovac.GetPortAt(1))]);
                th_hello2.Join();
                th_hello2 = null;
                th_waitTimer2.Join();
                th_waitTimer2 = null;
                OspfButt2.Content = "Zapnúť OSPF na porte 2";
            }
        }

        public Neighbor GetNeighbor(IPAddress router_id, IPAddress ip)
        {
            smerovac.mut_sused.WaitOne();
            foreach (Neighbor nei in smerovac.neighbors)
                if ((router_id == null && nei.ip_add.Equals(ip)) || (nei.neighbor_id.Equals(router_id) && nei.ip_add.Equals(ip)))
                {
                    smerovac.mut_sused.ReleaseMutex();
                    return nei;
                }
            smerovac.mut_sused.ReleaseMutex();
            return null;
        }

        public List<IPAddress> FullNeighbor(Port port)
        {
            List<IPAddress> ret = new List<IPAddress>();
            smerovac.mut_sused.WaitOne();
            foreach (Neighbor nei in smerovac.neighbors)
                if (nei.state == 6 && nei.output == port) ret.Add(nei.neighbor_id);
            smerovac.mut_sused.ReleaseMutex();
            return ret;
        }

        public void WaitTimer(Port port)
        {
            Thread.Sleep(40000);
            //smerovac.neighbors.Add(new Neighbor(IPAddress.Parse("2.2.2.2"), IPAddress.Parse("100.100.100.102"), 2, 10, 2, port,IPAddress.Parse("0.0.0.0"), IPAddress.Parse("0.0.0.0")));
            //smerovac.neighbors.Add(new Neighbor(IPAddress.Parse("4.4.4.4"), IPAddress.Parse("100.100.100.104"), 1, 40, 2, port, IPAddress.Parse("0.0.0.0"), IPAddress.Parse("0.0.0.0")));
            //smerovac.neighbors.Add(new Neighbor(IPAddress.Parse("6.6.6.6"), IPAddress.Parse("100.100.100.106"), 1, 30, 2, port, IPAddress.Parse("0.0.0.0"), IPAddress.Parse("0.0.0.0")));
            //smerovac.neighbors.Add(new Neighbor(IPAddress.Parse("8.8.8.8"), IPAddress.Parse("100.100.100.108"), 1, 20, 2, port, IPAddress.Parse("0.0.0.0"), IPAddress.Parse("0.0.0.0")));
            if (port.ospf && port.need_calculation) MakeElection(port);
            port.need_calculation = false;
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
                                if (n.priority > BDR.priority || (n.priority == BDR.priority && smerovac.GreaterIP(n.neighbor_id, BDR.neighbor_id) == n.neighbor_id))
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
                            if (n.priority > BDR.priority || (n.priority == BDR.priority && smerovac.GreaterIP(n.neighbor_id, BDR.neighbor_id) == n.neighbor_id))
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
                            if (n.priority > DR.priority || (n.priority == DR.priority && smerovac.GreaterIP(n.neighbor_id, DR.neighbor_id) == n.neighbor_id))
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

                if (smerovac.neighbors_changed)
                {
                    smerovac.neighbors_changed = false;
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
                }
                
                ip.Checksum = 0;
                ip.UpdateIPChecksum();
                
                hello.Checksum = 0;
                hello.Checksum = smerovac.ComputeChecksum(hello.HeaderData, 0, hello.HeaderData.Length);

                port.port.SendPacket(eth);
                Thread.Sleep(10000);
            }
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
            foreach (Neighbor n in smerovac.neighbors)
                if (n.neighbor_id.Equals(hello.RouterID) && n.ip_add.Equals(ip))
                {
                    n.dead_time = hello.RouterDeadInterval;
                    n.output = port;
                    if (hello.NeighborID.Contains(smerovac.routerID) && n.state < 2)
                    {
                        n.state = 2;
                        if (!port.need_calculation)
                            MakeElection(port);
                    }
                    if (n.state >= 2 && !port.need_calculation)
                    {
                        if (!n.dr.Equals(hello.DesignatedRouterID) && hello.DesignatedRouterID.Equals(ip))
                        {
                            n.dr = hello.DesignatedRouterID;
                            n.bdr = hello.BackupRouterID;
                            MakeElection(port);
                        }
                        if (!n.bdr.Equals(hello.BackupRouterID) && hello.BackupRouterID.Equals(ip))
                        {
                            n.dr = hello.DesignatedRouterID;
                            n.bdr = hello.BackupRouterID;
                            MakeElection(port);
                        }

                        if (n.dr.Equals(ip) && !hello.DesignatedRouterID.Equals(ip))
                        {
                            n.dr = hello.DesignatedRouterID;
                            n.bdr = hello.BackupRouterID;
                            MakeElection(port);
                        }
                        if (n.bdr.Equals(ip) && !hello.BackupRouterID.Equals(ip))
                        {
                            n.dr = hello.DesignatedRouterID;
                            n.bdr = hello.BackupRouterID;
                            MakeElection(port);
                        }
                        if (n.priority != hello.RtrPriority)
                        {
                            n.priority = hello.RtrPriority;
                            n.dr = hello.DesignatedRouterID;
                            n.bdr = hello.BackupRouterID;
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
                if (!port.need_calculation) MakeElection(port);
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
                
                smerovac.mut_sused.ReleaseMutex();

                foreach (Neighbor nei in vymazat)
                {
                    if (nei.state == 6)
                    {
                        MakeRouterLSA(nei.output, smerovac.ospf.DRs[smerovac.ports.IndexOf(nei.output)]);
                        if (smerovac.ospf.DRs[smerovac.ports.IndexOf(nei.output)].Equals(nei.output.ip_add))
                            MakeNetworkLSA(nei.output, smerovac.ospf.DRs[smerovac.ports.IndexOf(nei.output)]);
                    }
                }
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

            foreach(LSA lsa in smerovac.my_database)
            {
                newLSA = new LSA()
                {
                    AdvertisingRouter = lsa.AdvertisingRouter,
                    LSType = lsa.LSType,
                    LinkStateID = lsa.LinkStateID,
                    LSSequenceNumber = lsa.LSSequenceNumber,
                    LSAge = lsa.LSAge,
                    Options = lsa.Options,
                    Checksum = lsa.Checksum,
                    Length = lsa.Length
                };
                list_to_send.Add(newLSA);
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
            while(neighbor.state != 5)
            {
                Thread.Sleep(50);
            }
            Loading(neighbor, eth);
        }

        public void Loading(Neighbor neighbor, EthernetPacket eth)
        {
            Console.WriteLine(neighbor.neighbor_id + " TRANSITION TO LOADING");

            List<LinkStateRequest> request_list = new List<LinkStateRequest>();
            foreach(LSA lsa in neighbor.request_list)
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
            MakeRouterLSA(neighbor.output, smerovac.ospf.DRs[smerovac.ports.IndexOf(neighbor.output)]);
            if (smerovac.ospf.DRs[smerovac.ports.IndexOf(neighbor.output)].Equals(neighbor.output.ip_add))
                MakeNetworkLSA(neighbor.output, smerovac.ospf.DRs[smerovac.ports.IndexOf(neighbor.output)]);
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
                smerovac.ports[0].cost = int.Parse(CostPort1.Text);
            CostPort1.Text = "";
        }

        public void NastavCostPortu2(object sender, RoutedEventArgs e)
        {
            if (CostPort2.Text != "")
                smerovac.ports[1].cost = int.Parse(CostPort2.Text);
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
                if (rt.ip_add.Equals(novy.ip_add) && rt.maska.Equals(novy.maska) && rt.metric > novy.metric)
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
            RTListbox.Items.Clear();
            foreach (RT_zaznam rt in smerovac.smerovacia_tabulka)
                RTListbox.Items.Add(rt.Vypis());
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