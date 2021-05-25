import pyshark
import asyncio
import datetime
import time
from logging import getLogger
from scapy.all import wrpcap
from pyshark.packet.packet import Packet


class PacketCapture:
    """packet capture and print dict

    Attributes:
        interface (str)
        event_loop (asyncio.events.AbstractEventLoop)
        capture (pyshark.LiveCapture)
    """

    def __init__(self, interface, output_file):
        """init

        Args:
            interface (str) : interface name
            output_file (str) : output pcap file name
        """
        self.interface = interface
        self.event_loop = asyncio.get_event_loop()
        self._output_file = output_file
        self.capture = pyshark.LiveCapture(interface=self.interface, eventloop=self.event_loop, use_json=True, include_raw=True)

    def start(self, packet_count=None):
        """packet capture run"""
        try:
            coroutine = self.get_write_pcap_coro(packet_count)
            self.event_loop.run_until_complete(coroutine)
        except KeyboardInterrupt as e:
            print("finish")
            exit()

    def get_write_pcap_coro(self, packet_count):
        return self.capture.packets_from_tshark(self.write_pcap, packet_count=packet_count)

    def close(self):
        self.capture.close()

    def write_pcap(self, pkt, do_print=True):
        """write pcap file

        Args:
            pkt (Packet) : packet
            do_print (bool) : do print?
        """
        if do_print:
            print({pkt.sniff_timestamp: packet_to_dict(pkt)})
        wrpcap(self._output_file, pkt.get_raw_packet(), append=True)


def packet_to_dict(pkt):
    """packet to dict

    Args:
        pkt (Packet): packet
    """
    dict_fields = {}
    for layer in pkt.layers:
        dict_fields[layer.layer_name] = layer_to_dict(layer)['_all_fields']
    return dict_fields


def layer_to_dict(obj):
    """layer object to dict

    Args:
        obj (pyshark.packet.layer.Layer) : packet layer

    Returns:
        dict
    """
    if isinstance(obj, dict):
        data = {}
        for (k, v) in obj.items():
            k = k.split(".")  # layer field name
            k = k[len(k)-1]
            data[k] = layer_to_dict(v)
        return data
    elif hasattr(obj, "_ast"):
        return layer_to_dict(obj._ast())
    elif hasattr(obj, "__iter__") and not isinstance(obj, str):
        return [layer_to_dict(v) for v in obj]
    elif hasattr(obj, "__dict__"):
        return layer_to_dict(vars(obj))
    elif hasattr(obj, "__slots__"):
        data = layer_to_dict(dict((name, getattr(obj, name)) for name in getattr(obj, "__slots__")))
        return data
    else:
        return obj


if __name__ == '__main__':
    output_file = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S.pcap')
    capture = PacketCapture("en0", output_file)
    capture.start()
