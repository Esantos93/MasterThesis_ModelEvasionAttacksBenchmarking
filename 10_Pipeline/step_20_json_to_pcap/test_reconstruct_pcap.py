import unittest

from step_20_json_to_pcap.reconstruct_pcap import (
    apply_ethernet_minimum_padding,
    build_transport_layer,
    parse_tcp_options,
)


SUPPORTED = {"EOL", "NOP", "MSS", "WScale", "SAckOK", "SAck", "Timestamp"}


class FakeTCP:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class FakePacket:
    def __init__(self, data: bytes, timestamp: float = 0.0):
        self.data = data
        self.time = timestamp


def fake_ether(data: bytes) -> FakePacket:
    return FakePacket(data)


class TcpOptionReconstructionTests(unittest.TestCase):
    def test_parses_step14_display_string(self):
        value = "[('MSS', 1460), ('SAckOK', b''), ('Timestamp', (19603392, 0)), ('NOP', None), ('WScale', 7)]"

        options = parse_tcp_options(value, SUPPORTED)

        self.assertEqual(
            options,
            [
                ("MSS", 1460),
                ("SAckOK", b""),
                ("Timestamp", (19603392, 0)),
                ("NOP", None),
                ("WScale", 7),
            ],
        )

    def test_literal_eval_does_not_execute_expressions(self):
        with self.assertRaisesRegex(ValueError, "not a valid literal"):
            parse_tcp_options("__import__('os').system('echo unsafe')", SUPPORTED)

    def test_rejects_unsupported_named_option(self):
        with self.assertRaisesRegex(ValueError, "unsupported name"):
            parse_tcp_options("[('NotATcpOption', 1)]", SUPPORTED)

    def test_transport_layer_receives_validated_options(self):
        issues = []
        transport = build_transport_layer(
            {
                "transport_protocol": "TCP",
                "src_port": 1234,
                "dst_port": 80,
                "tcp_flags": 2,
                "options": "[('MSS', 1460), ('WScale', 7)]",
            },
            {
                "TCP": FakeTCP,
                "UDP": object,
                "ICMP": object,
                "TCP_OPTION_NAMES": frozenset(SUPPORTED),
            },
            issues,
        )

        self.assertEqual(issues, [])
        self.assertEqual(transport.kwargs["options"], [("MSS", 1460), ("WScale", 7)])

    def test_invalid_options_create_error_and_are_not_silently_omitted(self):
        issues = []
        build_transport_layer(
            {
                "transport_protocol": "TCP",
                "src_port": 1234,
                "dst_port": 80,
                "tcp_flags": 2,
                "options": "[('NotATcpOption', 1)]",
            },
            {
                "TCP": FakeTCP,
                "UDP": object,
                "ICMP": object,
                "TCP_OPTION_NAMES": frozenset(SUPPORTED),
            },
            issues,
        )

        self.assertEqual(issues[0]["severity"], "error")
        self.assertEqual(issues[0]["reason"], "tcp_options_invalid")


class EthernetPaddingTests(unittest.TestCase):
    def test_adds_padding_outside_serialized_packet_to_sixty_bytes(self):
        packet = FakePacket(b"x" * 54, timestamp=123.5)

        padded, serialized, padding_length = apply_ethernet_minimum_padding(
            packet,
            {"raw": lambda value: value.data, "Ether": fake_ether},
        )

        self.assertEqual(len(serialized), 60)
        self.assertEqual(serialized[-6:], b"\x00" * 6)
        self.assertEqual(padding_length, 6)
        self.assertEqual(padded.time, 123.5)

    def test_does_not_modify_frames_already_at_minimum_size(self):
        packet = FakePacket(b"x" * 60, timestamp=123.5)

        padded, serialized, padding_length = apply_ethernet_minimum_padding(
            packet,
            {"raw": lambda value: value.data, "Ether": fake_ether},
        )

        self.assertIs(padded, packet)
        self.assertEqual(serialized, b"x" * 60)
        self.assertEqual(padding_length, 0)


if __name__ == "__main__":
    unittest.main()
