"""Parser de la salida XML de nmap con ``defusedxml`` (XXE / XML bombs)."""

from defusedxml import ElementTree

from apps.assets.contracts import DiscoveredHost, DiscoveredService


class NmapParseError(ValueError):
    pass


def _best_os(host):
    matches = host.findall("os/osmatch")
    if not matches:
        return ""
    best = max(matches, key=lambda m: int(m.get("accuracy", "0") or 0))
    return best.get("name", "")


def _service(port):
    state = port.find("state")
    svc = port.find("service")
    cpe = port.find("service/cpe")
    banner = port.find("script[@id='banner']")
    return DiscoveredService(
        port=int(port.get("portid")),
        protocol=port.get("protocol", "tcp"),
        state=state.get("state", "open") if state is not None else "open",
        service_name=svc.get("name", "") if svc is not None else "",
        product=svc.get("product", "") if svc is not None else "",
        version=svc.get("version", "") if svc is not None else "",
        extra_info=svc.get("extrainfo", "") if svc is not None else "",
        cpe=cpe.text or "" if cpe is not None else "",
        banner=banner.get("output", "") if banner is not None else "",
    )


def parse_nmap_xml(xml, *, observed_at, services_complete):
    """Hosts activos como ``DiscoveredHost``. Los puertos solo cuentan en escaneos de servicios."""
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as exc:
        raise NmapParseError(f"XML de nmap inválido: {exc}") from exc
    except Exception as exc:  # defusedxml: entidades, DTD externos
        raise NmapParseError(f"XML de nmap rechazado: {type(exc).__name__}") from exc
    if root.tag != "nmaprun":
        raise NmapParseError("El documento no es una salida XML de nmap.")
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addresses = {a.get("addrtype"): a.get("addr") for a in host.findall("address")}
        hostnames = tuple(
            dict.fromkeys(
                h.get("name") for h in host.findall("hostnames/hostname") if h.get("name")
            )
        )
        services = tuple(
            _service(p) for p in host.findall("ports/port") if p.get("portid", "").isdigit()
        )
        hosts.append(
            DiscoveredHost(
                source="nmap",
                observed_at=observed_at,
                ipv4=addresses.get("ipv4"),
                ipv6=addresses.get("ipv6"),
                mac=addresses.get("mac"),
                hostnames=hostnames,
                os_guess=_best_os(host),
                services=services,
                services_complete=services_complete and bool(host.find("ports") is not None),
            )
        )
    return hosts
