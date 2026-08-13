"""Secret-safe helpers for ExpressRoute Direct Data Link checks."""

from enum import Enum
from typing import Any, Iterator, Tuple


class InventoryState(str, Enum):
    """Applicability state for ExpressRoute Direct inventory."""

    APPLICABLE = "APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INDETERMINATE = "INDETERMINATE"


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


def inventory_state(ports: Any) -> InventoryState:
    """Distinguish inventory absence from an Azure API failure."""
    if ports is None:
        return InventoryState.INDETERMINATE
    if not ports:
        return InventoryState.NOT_APPLICABLE
    return InventoryState.APPLICABLE


def has_macsec(link: Any) -> bool:
    """Return whether a link has a MACsec configuration without reading secrets."""
    return value(link, "mac_sec_config") is not None


def cipher_name(link: Any) -> str:
    """Return only the non-secret MACsec cipher identifier."""
    config = value(link, "mac_sec_config")
    cipher = value(config, "cipher", "") if config is not None else ""
    return str(getattr(cipher, "value", cipher))


def resource_identity(port: Any, link: Any) -> tuple[str, str, str]:
    """Build non-secret resource identity fields for a finding."""
    port_id = str(value(port, "id", ""))
    port_name = str(value(port, "name", "ExpressRoute Direct port"))
    link_name = str(value(link, "name", value(link, "interface_name", "link")))
    link_id = str(value(link, "id", "")) or f"{port_id.rstrip('/')}/links/{link_name}"
    return link_id, f"{port_name}/{link_name}", link_name
