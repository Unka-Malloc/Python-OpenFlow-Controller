from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet.ether_types import ETH_TYPE_IP

class L4State14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4State14, self).__init__(*args, **kwargs)
        self.ht = set()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        acts = [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, psr.OFPMatch(), acts)

    def add_flow(self, dp, prio, match, acts, buffer_id=None):
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        bid = buffer_id if buffer_id is not None else ofp.OFP_NO_BUFFER
        ins = [psr.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts)]
        mod = psr.OFPFlowMod(datapath=dp, buffer_id=bid, priority=prio,
                                match=match, instructions=ins)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port, pkt = (msg.match['in_port'], packet.Packet(msg.data))
        dp = msg.datapath
        ofp, psr, did = (dp.ofproto, dp.ofproto_parser, format(dp.id, '016d'))
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        # code start
        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(did, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[did][src] = in_port

        if dst in self.mac_to_port[did]:
            out_port = self.mac_to_port[did][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        l2_learning_actions = [psr.OFPActionOutput(out_port)]
        actions = [psr.OFPActionOutput(out_port),
                   psr.OFPActionOutput(self.snort_port)]
        if out_port != ofp.OFPP_FLOOD:
            match = psr.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(dp, 1, match, l2_learning_actions)

            # Detect HTTP server traffic
            match_http_out = psr.OFPMatch(in_port=in_port,
                                             eth_dst=dst,
                                             eth_type=ethernet.ETH_TYPE_IP,
                                             ip_proto=in_proto.IPPROTO_TCP,
                                             tcp_dst=80)

            match_irc_in = psr.OFPMatch(in_port=in_port,
                                           eth_dst=dst,
                                           eth_type=ethernet.ETH_TYPE_IP,
                                           ip_proto=in_proto.IPPROTO_TCP,
                                           tcp_src=6667)

            self.add_flow(dp, 10, match_http_out, actions)
            self.add_flow(dp, 10, match_irc_in, actions)

            # Detect Ping packet
            match_ping = psr.OFPMatch(in_port=in_port,
                                         eth_dst=dst,
                                         eth_type=ethernet.ETH_TYPE_IP,
                                         ip_proto=in_proto.IPPROTO_ICMP)

            self.add_flow(dp, 10, match_ping, actions)

        # For packet-out
        acts = l2_learning_actions
        # code end
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                               in_port=in_port, actions=acts, data=data)
        dp.send_msg(out)
