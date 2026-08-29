"""Explainable, deterministic device profiling; never presents inference as fact."""

from __future__ import annotations

from dataclasses import asdict, dataclass

DEVICE_TYPES = {
    "Phone", "Tablet", "Laptop", "Desktop", "Router", "Access Point",
    "Smart TV", "Streaming Device", "Printer", "NAS", "Server", "Camera",
    "IoT", "Game Console", "Virtual Machine", "Unknown",
}


@dataclass(frozen=True)
class ProfileEvidence:
    signal: str
    value: str
    contribution: int
    explanation: str


@dataclass(frozen=True)
class DeviceProfile:
    device_type: str
    label: str
    confidence: float
    evidence: tuple[ProfileEvidence, ...]

    def to_dict(self) -> dict:
        return {
            "device_type": self.device_type, "label": self.label,
            "confidence": self.confidence,
            "evidence": [asdict(item) for item in self.evidence],
            "disclaimer": "Device type is an explainable estimate, not a confirmed fact.",
        }


_VENDOR_RULES = {
    "Printer": ("brother", "canon", "epson", "lexmark", "xerox"),
    "NAS": ("synology", "qnap"),
    "Camera": ("hikvision", "dahua", "axis communications", "reolink", "ring llc"),
    "Game Console": ("nintendo", "playstation", "sony interactive", "xbox"),
    "Virtual Machine": ("vmware", "virtualbox", "qemu", "xen", "parallels"),
    "Router": ("ubiquiti", "tp-link", "netgear", "mikrotik", "cisco", "juniper", "sagemcom"),
    "Smart TV": ("samsung", "lg electronics", "vizio"),
    "Streaming Device": ("roku", "chromecast", "amazon technologies", "bose corporation"),
    # Apple/Google/Intel vendors span phones, tablets and computers, so a
    # vendor match alone must not force one of those categories.
    "Phone": ("xiaomi", "oppo", "oneplus", "motorola", "huawei"),
}

_PORT_RULES = {
    "Printer": {515, 631, 9100},
    "NAS": {2049, 3260, 5000, 5001},
    "Camera": {554, 8554},
    "Smart TV": {8008, 8009, 9080},
    "Server": {22, 25, 80, 443, 3306, 5432},
    "Router": {53, 67, 68},
}


def infer_device_profile(signals: dict) -> DeviceProfile:
    vendor = str(signals.get("vendor") or "").strip()
    hostname = str(signals.get("hostname") or "").strip()
    protocols = {str(item).lower() for item in signals.get("protocols", [])}
    services = {str(item).lower() for item in signals.get("services", [])}
    try:
        ports = {int(item) for item in signals.get("open_ports", [])}
    except (TypeError, ValueError):
        ports = set()
    scores = dict.fromkeys(DEVICE_TYPES, 0)
    evidence: dict[str, list[ProfileEvidence]] = {kind: [] for kind in DEVICE_TYPES}

    def add(kind: str, signal: str, value, points: int, explanation: str) -> None:
        scores[kind] += points
        evidence[kind].append(ProfileEvidence(signal, str(value), points, explanation))

    vendor_lower = vendor.lower()
    for kind, needles in _VENDOR_RULES.items():
        if any(needle in vendor_lower for needle in needles):
            add(kind, "mac_vendor", vendor, 35, f"MAC vendor is commonly associated with {kind.lower()} devices")

    hostname_lower = hostname.lower()
    hostname_rules = {
        "Phone": ("iphone", "android", "pixel", "galaxy"),
        "Tablet": ("ipad", "tablet"), "Printer": ("printer", "epson", "brother"),
        "NAS": ("nas", "synology", "qnap"), "Camera": ("camera", "cam-", "ipc"),
        "Smart TV": ("smarttv", "bravia", "webos", "tizen"),
        "Game Console": ("xbox", "playstation", "nintendo"),
        "Router": ("router", "gateway"), "Access Point": ("access-point", "ap-"),
    }
    for kind, needles in hostname_rules.items():
        if hostname and any(needle in hostname_lower for needle in needles):
            add(kind, "hostname", hostname, 35, f"Hostname resembles a {kind.lower()}")

    if signals.get("is_gateway"):
        add("Router", "network_role", "default gateway", 70, "Device is the configured default gateway")
    if signals.get("randomized_mac"):
        add("Phone", "mac_address", "locally administered", 15, "Privacy MACs are common on mobile devices")

    for kind, known_ports in _PORT_RULES.items():
        matched = sorted(ports & known_ports)
        if matched:
            points = min(40, 12 + len(matched) * 8)
            add(kind, "open_ports", ", ".join(map(str, matched)), points,
                f"Observed ports are commonly used by {kind.lower()} devices")

    if {"airplay", "raop"} & protocols:
        add("Streaming Device", "protocols", sorted(protocols & {"airplay", "raop"}), 30,
            "AirPlay/RAOP is characteristic of media endpoints")
    if {"ssdp", "upnp", "dlna"} & protocols:
        add("Smart TV", "protocols", sorted(protocols & {"ssdp", "upnp", "dlna"}), 20,
            "UPnP/DLNA discovery is common for smart TVs and media devices")
    if {"ipp", "printer"} & services:
        add("Printer", "services", sorted(services & {"ipp", "printer"}), 40,
            "Printer service was observed")
    if {"rtsp"} & services or {"rtsp"} & protocols:
        add("Camera", "services", "rtsp", 40, "RTSP is commonly exposed by IP cameras")
    if {445, 2049} & ports:
        add("NAS", "file_services", sorted({445, 2049} & ports), 25,
            "Network file-sharing service was observed")

    winner = max(scores, key=scores.get)
    score = scores[winner]
    if score < 20:
        return DeviceProfile("Unknown", "Unknown device", 0.2, ())
    confidence = min(0.95, 0.35 + score / 140)
    label_vendor = vendor.split(" ")[0] if vendor else "Likely"
    return DeviceProfile(winner, f"{label_vendor} {winner}", round(confidence, 2), tuple(evidence[winner]))
