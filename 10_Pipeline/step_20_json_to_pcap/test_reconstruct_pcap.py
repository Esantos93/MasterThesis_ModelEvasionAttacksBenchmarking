import unittest

from step_20_json_to_pcap.reconstruct_pcap import build_transport_layer, parse_tcp_options


SUPPORTED = {"EOL", "NOP", "MSS", "WScale", "SAckOK", "SAck", "Timestamp"}


class FakeTCP:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


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


if __name__ == "__main__":
    unittest.main()
