"""Secret-safe helpers for ExpressRoute Direct Data Link checks."""

from typing import Any, Iterator, Tuple


def value(item: Any, field: str, default: Any = None) -> Any:
    """Read an SDK model or test dictionary field."""
    if isinstance(item, dict):
        return item.get(field, default)
    return getattr(item, field, default)


def enabled_links(port: Any) -> Iterator[Tuple[Any, Any]]:
    """Yield enabled links with their parent port."""
    for link in value(port, "links", []) or []:
        state = str(getattr(value(link, "admin_state", ""), "value", value(link, "admin_state", "")))
        if state.lower() == "enabled":
            yield port, link


def has_macsec(link: Any) -> bool:
    """Return whether a link has a MACsec configuration without reading secrets."""
    return value(link, "macsec_config") is not None


def cipher_name(link: Any) -> str:
    """Return only the non-secret MACsec cipher identifier."""
    config = value(link, "macsec_config")
    cipher = value(config, "cipher", "") if config is not None else ""
    return str(getattr(cipher, "value", cipher))


def resource_identity(port: Any, link: Any) -> tuple[str, str, str]:
    """Build non-secret resource identity fields for a finding."""
    port_id = str(value(port, "id", ""))
    port_name = str(value(port, "name", "ExpressRoute Direct port"))
    link_name = str(value(link, "name", value(link, "interface_name", "link")))
    return port_id, port_name, link_name
