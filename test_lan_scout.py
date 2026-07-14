import json
import os
import tempfile
import unittest

from lan_scout import parse_ports, check_port, save_results, COMMON_PORTS


class TestParsePorts(unittest.TestCase):

    def test_known_ports(self):
        result = parse_ports("22,80,443")
        self.assertEqual(result[22], "SSH")
        self.assertEqual(result[80], "HTTP")
        self.assertEqual(result[443], "HTTPS")

    def test_unknown_port_gets_labeled_custom(self):
        result = parse_ports("9999")
        self.assertEqual(result[9999], "Custom")

    def test_handles_spaces(self):
        result = parse_ports("22, 80 , 443")
        self.assertEqual(set(result.keys()), {22, 80, 443})

    def test_matches_common_ports_dict(self):
        # just making sure parse_ports agrees with the hardcoded dict
        result = parse_ports("22")
        self.assertEqual(result[22], COMMON_PORTS[22])


class TestCheckPort(unittest.TestCase):

    def test_closed_port_returns_false(self):
        # high port that shouldn't be listening on localhost
        self.assertFalse(check_port("127.0.0.1", 54321, timeout=0.2))


class TestSaveResults(unittest.TestCase):

    def setUp(self):
        self.sample = [
            {"ip": "192.168.1.2", "hostname": "router.local", "ports": ["80/HTTP", "443/HTTPS"]},
            {"ip": "192.168.1.10", "hostname": "Unknown", "ports": []},
        ]

    def test_saves_json(self):
        path = os.path.join(tempfile.gettempdir(), "test_results.json")
        save_results(self.sample, path)
        with open(path) as f:
            data = json.load(f)
        self.assertEqual(len(data), 2)
        os.remove(path)

    def test_saves_csv(self):
        path = os.path.join(tempfile.gettempdir(), "test_results.csv")
        save_results(self.sample, path)
        with open(path) as f:
            content = f.read()
        self.assertIn("192.168.1.2", content)
        os.remove(path)


if __name__ == "__main__":
    unittest.main()
