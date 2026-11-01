"""Parseur de la sortie XML Nmap (-oX -) vers le schema interne du parser.

Principes :
- On ne devine jamais une valeur manquante silencieusement : un champ absent
  devient `None` (ou une valeur "unknown" explicite pour `state`), et une
  entree est ajoutee a `parse_errors` -- jamais d'exception qui ferait
  perdre tout le reste d'un scan a cause d'un seul hote mal forme.
- Seule une sortie XML structurellement invalide (pas du XML du tout, ou
  racine differente de <nmaprun>) fait lever `NmapParseError` : dans ce cas
  il n'y a rien d'exploitable a extraire.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from recon_copilot.parser.models import (
    ExtraPortsSummary,
    NmapParseResult,
    NmapScriptOutput,
    ParsedHost,
    ParsedPort,
)


class NmapParseError(Exception):
    """Leve quand la sortie n'est pas du XML Nmap exploitable (vide, tronque, racine inattendue)."""


def _fragment(element: ET.Element) -> str:
    return ET.tostring(element, encoding="unicode").strip()


def _parse_port(port_el: ET.Element, errors: list[str], host_ip: str) -> ParsedPort:
    number = int(port_el.get("portid", "-1"))
    protocol = port_el.get("protocol", "unknown")

    state_el = port_el.find("state")
    if state_el is None:
        errors.append(f"{host_ip}:{number}/{protocol} -- element <state> absent, marque 'unknown'")
        state = "unknown"
    else:
        state = state_el.get("state", "unknown")

    service_el = port_el.find("service")
    service_name = service_el.get("name") if service_el is not None else None
    product = service_el.get("product") if service_el is not None else None
    version = service_el.get("version") if service_el is not None else None
    extra_info = service_el.get("extrainfo") if service_el is not None else None

    scripts = tuple(
        NmapScriptOutput(
            script_id=script_el.get("id", "unknown"),
            output=script_el.get("output", ""),
            source_fragment=_fragment(script_el),
        )
        for script_el in port_el.findall("script")
    )

    return ParsedPort(
        number=number,
        protocol=protocol,
        state=state,
        service_name=service_name,
        product=product,
        version=version,
        extra_info=extra_info,
        scripts=scripts,
        source_fragment=_fragment(port_el),
    )


def _parse_host(host_el: ET.Element, errors: list[str]) -> ParsedHost | None:
    address_el = host_el.find("address")
    if address_el is None or not address_el.get("addr"):
        errors.append("element <host> sans <address addr=...> exploitable -- hote ignore")
        return None
    ip = address_el.get("addr")

    status_el = host_el.find("status")
    status = status_el.get("state", "unknown") if status_el is not None else "unknown"
    if status_el is None:
        errors.append(f"{ip} -- element <status> absent, marque 'unknown'")

    hostnames = tuple(
        hn.get("name", "")
        for hn in host_el.findall("hostnames/hostname")
        if hn.get("name")
    )

    ports = tuple(
        _parse_port(port_el, errors, ip) for port_el in host_el.findall("ports/port")
    )

    extraports = tuple(
        ExtraPortsSummary(
            state=ep_el.get("state", "unknown"),
            count=int(ep_el.get("count", "0")),
            source_fragment=_fragment(ep_el),
        )
        for ep_el in host_el.findall("ports/extraports")
    )

    return ParsedHost(
        ip=ip,
        hostnames=hostnames,
        status=status,
        ports=ports,
        extraports=extraports,
        source_fragment=_fragment(host_el),
    )


def parse_nmap_xml(raw_xml: str) -> NmapParseResult:
    """Normalise une sortie Nmap -oX en NmapParseResult.

    Leve NmapParseError si `raw_xml` n'est pas du XML Nmap exploitable
    (chaine vide, XML tronque/invalide, ou racine != <nmaprun>) -- c'est le
    cas typique d'un scan tue par timeout avant d'avoir ecrit sa sortie.
    """
    if not raw_xml or not raw_xml.strip():
        raise NmapParseError("sortie Nmap vide -- rien a parser (scan probablement echoue/timeout)")

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as exc:
        raise NmapParseError(f"XML Nmap invalide ou tronque: {exc}") from exc

    if root.tag != "nmaprun":
        raise NmapParseError(f"racine XML inattendue '{root.tag}', attendu 'nmaprun'")

    errors: list[str] = []
    hosts = tuple(
        parsed
        for host_el in root.findall("host")
        if (parsed := _parse_host(host_el, errors)) is not None
    )

    return NmapParseResult(hosts=hosts, parse_errors=tuple(errors))
