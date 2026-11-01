from __future__ import annotations

from pathlib import Path

import pytest

from recon_copilot.parser.nmap_parser import NmapParseError, parse_nmap_xml

FIXTURE = (Path(__file__).parent / "fixtures" / "sample_nmap.xml").read_text()


def test_parses_two_hosts():
    result = parse_nmap_xml(FIXTURE)
    assert len(result.hosts) == 2
    ips = {h.ip for h in result.hosts}
    assert ips == {"10.0.0.5", "10.0.0.6"}


def test_up_host_has_hostnames_and_ports():
    result = parse_nmap_xml(FIXTURE)
    host = next(h for h in result.hosts if h.ip == "10.0.0.5")
    assert host.status == "up"
    assert host.hostnames == ("app.client.local",)
    assert len(host.ports) == 3


def test_down_host_has_no_ports():
    result = parse_nmap_xml(FIXTURE)
    host = next(h for h in result.hosts if h.ip == "10.0.0.6")
    assert host.status == "down"
    assert host.ports == ()


def test_port_service_fields_extracted():
    result = parse_nmap_xml(FIXTURE)
    host = next(h for h in result.hosts if h.ip == "10.0.0.5")
    ssh_port = next(p for p in host.ports if p.number == 22)
    assert ssh_port.state == "open"
    assert ssh_port.service_name == "ssh"
    assert ssh_port.product == "OpenSSH"
    assert ssh_port.version == "8.9p1"


def test_extraports_grouped_ports_are_captured():
    result = parse_nmap_xml(FIXTURE)
    host = next(h for h in result.hosts if h.ip == "10.0.0.5")
    assert len(host.extraports) == 1
    summary = host.extraports[0]
    assert summary.state == "filtered"
    assert summary.count == 97
    assert "<extraports" in summary.source_fragment


def test_down_host_has_no_extraports():
    result = parse_nmap_xml(FIXTURE)
    host = next(h for h in result.hosts if h.ip == "10.0.0.6")
    assert host.extraports == ()


def test_filtered_port_state_preserved():
    result = parse_nmap_xml(FIXTURE)
    host = next(h for h in result.hosts if h.ip == "10.0.0.5")
    port_139 = next(p for p in host.ports if p.number == 139)
    assert port_139.state == "filtered"


def test_script_output_captured_with_source_fragment():
    result = parse_nmap_xml(FIXTURE)
    host = next(h for h in result.hosts if h.ip == "10.0.0.5")
    http_port = next(p for p in host.ports if p.number == 80)
    assert len(http_port.scripts) == 1
    script = http_port.scripts[0]
    assert script.script_id == "http-title"
    assert "nginx" in script.output
    assert "<script" in script.source_fragment


def test_source_fragment_is_exact_xml_for_host():
    result = parse_nmap_xml(FIXTURE)
    host = next(h for h in result.hosts if h.ip == "10.0.0.5")
    assert host.source_fragment.startswith("<host>")
    assert '10.0.0.5' in host.source_fragment


def test_empty_output_raises_nmap_parse_error():
    with pytest.raises(NmapParseError):
        parse_nmap_xml("")


def test_whitespace_only_output_raises():
    with pytest.raises(NmapParseError):
        parse_nmap_xml("   \n  ")


def test_truncated_xml_raises():
    with pytest.raises(NmapParseError):
        parse_nmap_xml("<nmaprun><host><address addr=")


def test_unexpected_root_raises():
    with pytest.raises(NmapParseError):
        parse_nmap_xml("<somethingelse/>")


def test_host_without_address_is_skipped_and_logged():
    xml = "<nmaprun><host><status state=\"up\"/></host></nmaprun>"
    result = parse_nmap_xml(xml)
    assert result.hosts == ()
    assert len(result.parse_errors) == 1
    assert "address" in result.parse_errors[0]


def test_port_without_state_defaults_to_unknown_and_logs():
    xml = (
        "<nmaprun><host><status state=\"up\"/><address addr=\"1.2.3.4\"/>"
        "<ports><port protocol=\"tcp\" portid=\"80\">"
        "<service name=\"http\"/></port></ports></host></nmaprun>"
    )
    result = parse_nmap_xml(xml)
    port = result.hosts[0].ports[0]
    assert port.state == "unknown"
    assert any("state" in e for e in result.parse_errors)
