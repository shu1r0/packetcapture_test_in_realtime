import pyshark
import asyncio
import pprint


class PacketCapture:
    """packet capture and print dict

    Attributes:
        interface (str)
        event_loop (asyncio.events.AbstractEventLoop)
        capture (pyshark.LiveCapture)
    """

    def __init__(self, interface):
        """init

        Args:
            interface (str) : interface name
        """
        self.interface = interface
        self.event_loop = asyncio.get_event_loop()
        self.capture = pyshark.LiveCapture(interface=self.interface, use_json=True)

    def start(self, packet_count=None):
        """packet capture start"""
        try:
            coroutine = self.capture.packets_from_tshark(self.packet_callback, packet_count=packet_count)
            self.event_loop.run_until_complete(coroutine)
        except KeyboardInterrupt as e:
            print("finish")
            exit()

    def packet_callback(self, pkt):
        """print packet

        Args:
            pkt (pyshark.packet.packet) : packet
        """
        pprint.pprint({pkt.sniff_timestamp: packet_to_dict(pkt)})


def packet_to_dict(pkt):
    """packet to dict

    Args:
        pkt (pyshark.packet.packet): packet
    """
    dict_fields = {}
    for layer in pkt.layers:
        dict_fields[layer.layer_name] = layer_to_dict(layer)['_all_fields']
    return dict_fields


def layer_to_dict(obj):
    """layer object to dict

    Args:
        obj (pyshark.packet.layer) : packet layer

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
    capture = PacketCapture("en0")
    capture.start(packet_count=10)
