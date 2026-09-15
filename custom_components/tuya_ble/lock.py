"""The Tuya BLE lock integration."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from struct import pack
from typing import TYPE_CHECKING, Any

from homeassistant.components.lock import (
    LockEntity,
    LockEntityDescription,
)
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.event import async_call_later

from .const import DOMAIN
from .devices import TuyaBLECoordinator, TuyaBLEData, TuyaBLEEntity, TuyaBLEProductInfo
from .tuya_ble import TuyaBLEDataPointType, TuyaBLEDevice

if TYPE_CHECKING:
    from datetime import datetime

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

_LOGGER = logging.getLogger(__name__)

# One-time remote code protocol (Tuya BLE lock DP reference):
# remote_no_pd_setkey (DP 60) registers an 8 digit ASCII code for a member:
#   validity (1), member ID (2), start time (4), end time (4),
#   usable times (2, 0 = unlimited), code (8)
# remote_no_dp_key (DP 61) then unlocks with that code:
#   action (1), member ID (2), code (8), unlock source (2)
# The lock replies to both with: result (1), member ID (2)
CODE_VALID = 0x01
CODE_UNLOCK = 0x01
CODE_SOURCE_APP = 0x0001
CODE_USABLE_TIMES = 1
# Tolerance around "now" for the code validity window, covers lock clock drift
CODE_CLOCK_SKEW = 300

CODE_RESULTS = {
    0x01: "failure",
    0x02: "password error",
    0x03: "timeout",
    0x04: "outside of the validity period",
    0x05: "wrong code",
    0x06: "double locked",
}

# Seconds to wait for the lock to answer a raw command
REPLY_TIMEOUT = 5
# Seconds to show locking/unlocking before falling back to the reported state
PENDING_TIMEOUT = 15


def build_set_code_payload(code: str, member_id: int, now: int) -> bytes:
    """Build a remote_no_pd_setkey value registering a single-use code."""
    return (
        pack(
            ">BHIIH",
            CODE_VALID,
            member_id,
            now - CODE_CLOCK_SKEW,
            now + CODE_CLOCK_SKEW,
            CODE_USABLE_TIMES,
        )
        + code.encode("ascii")
    )


def build_code_unlock_payload(code: str, member_id: int) -> bytes:
    """Build a remote_no_dp_key value unlocking with a registered code."""
    return (
        pack(">BH", CODE_UNLOCK, member_id)
        + code.encode("ascii")
        + pack(">H", CODE_SOURCE_APP)
    )


@dataclass
class TuyaBLELockMapping:
    """Mapping for Tuya BLE Lock."""

    lock_dp_id: int  # DP for controlling lock (automatic_lock)
    state_dp_id: int  # DP for reading lock state (lock_motor_state)
    reverse: bool
    description: LockEntityDescription | None = None


@dataclass
class TuyaBLECodeLockMapping:
    """Mapping for a Tuya BLE Lock unlocked with a one-time remote code.

    The integration registers a random code with remote_no_pd_setkey and
    immediately unlocks with it through remote_no_dp_key, so no key from the
    Tuya cloud is needed. Locking uses manual_lock.
    """

    manual_lock_dp_id: int = 46  # manual_lock
    state_dp_id: int = 47  # lock_motor_state: False = locked, True = unlocked
    set_code_dp_id: int = 60  # remote_no_pd_setkey
    unlock_code_dp_id: int = 61  # remote_no_dp_key
    code_member_id: int = 7  # member slot the one-time code is registered for
    description: LockEntityDescription = field(
        default_factory=lambda: LockEntityDescription(key="lock", name=None)
    )


@dataclass
class TuyaBLECategoryLockMapping:
    """Mapping for Tuya BLE Lock by category."""

    products: (
        dict[str, list[TuyaBLELockMapping | TuyaBLECodeLockMapping]] | None
    ) = None


category_mapping: dict[str, TuyaBLECategoryLockMapping] = {
    "ms": TuyaBLECategoryLockMapping(
        products={
            "0qxp5u7s": [  # Smart Lock
                TuyaBLELockMapping(
                    lock_dp_id=33,  # automatic_lock
                    state_dp_id=47,  # lock_motor_state (read-only)
                    reverse=True,
                    description=LockEntityDescription(
                        key="lock",
                        name="Lock",
                    ),
                ),
            ],
            "lmfdx8in": [  # Smart Lock T83 (YSG_T83_NO_NFC)
                TuyaBLECodeLockMapping(),
            ],
        },
    ),
}


def get_mapping_by_device(
    device: TuyaBLEDevice,
) -> list[TuyaBLELockMapping | TuyaBLECodeLockMapping]:
    """Get lock mappings for device."""
    category = device.category
    product_id = device.product_id
    mappings: list[TuyaBLELockMapping | TuyaBLECodeLockMapping] = []

    if category in category_mapping:
        category_map = category_mapping[category]
        if category_map.products and product_id in category_map.products:
            mappings.extend(category_map.products[product_id])

    return mappings


class TuyaBLELock(TuyaBLEEntity, LockEntity):
    """Representation of a Tuya BLE Lock."""

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLECoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLELockMapping,
    ) -> None:
        """Initialize the lock."""
        description = mapping.description or LockEntityDescription(
            key="lock",
            name="Lock",
        )
        super().__init__(hass, coordinator, device, product, description)
        self._mapping = mapping
        self._target_state: bool | None = None
        self._current_state: bool | None = None

    @property
    def is_locked(self) -> bool | None:
        """Return true if the lock is locked."""
        return self._target_state is True and self._current_state is not False

    @property
    def is_locking(self) -> bool:
        """Return true if the lock is locking."""
        return self._target_state is True and self._current_state is False

    @property
    def is_unlocking(self) -> bool:
        """Return true if the lock is unlocking."""
        return self._target_state is False and self._current_state is True

    async def async_lock(self, **_kwargs) -> None:
        """Lock the lock."""

        self._target_state = not self._mapping.reverse
        self.async_write_ha_state()

        datapoint = self._device.datapoints.get_or_create(
            self._mapping.lock_dp_id,
            TuyaBLEDataPointType.DT_BOOL,
            not self._mapping.reverse,
        )

        if datapoint:
            self._hass.create_task(datapoint.set_value(not self._mapping.reverse))

    async def async_unlock(self, **_kwargs) -> None:
        """Unlock the lock."""

        self._target_state = self._mapping.reverse
        self.async_write_ha_state()

        datapoint = self._device.datapoints.get_or_create(
            self._mapping.lock_dp_id,
            TuyaBLEDataPointType.DT_BOOL,
            self._mapping.reverse,
        )

        if datapoint:
            self._hass.create_task(datapoint.set_value(self._mapping.reverse))

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        # Check both lock_motor_state and automatic_lock datapoints for changes
        lock_datapoint = self._device.datapoints[self._mapping.lock_dp_id]
        if lock_datapoint:
            self._target_state = self._mapping.reverse ^ bool(lock_datapoint.value)

        if self._mapping.state_dp_id > 0:
            state_datapoint = self._device.datapoints[self._mapping.state_dp_id]
            if state_datapoint:
                self._current_state = self._mapping.reverse ^ bool(
                    state_datapoint.value
                )

        self.async_write_ha_state()


class TuyaBLECodeLock(TuyaBLEEntity, LockEntity):
    """Representation of a Tuya BLE Lock unlocked with a one-time code."""

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLECoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLECodeLockMapping,
    ) -> None:
        """Initialize the lock."""
        super().__init__(hass, coordinator, device, product, mapping.description)
        self._mapping = mapping
        # True while locking, False while unlocking, None when idle
        self._pending: bool | None = None
        self._unsub_pending: CALLBACK_TYPE | None = None
        self._reply_waiters: dict[int, asyncio.Future[int]] = {}

    @property
    def is_locked(self) -> bool | None:
        """Return true if the lock is locked."""
        datapoint = self._device.datapoints[self._mapping.state_dp_id]
        if datapoint is None:
            return None
        return not datapoint.value

    @property
    def is_locking(self) -> bool:
        """Return true if the lock is locking."""
        return self._pending is True

    @property
    def is_unlocking(self) -> bool:
        """Return true if the lock is unlocking."""
        return self._pending is False

    async def async_lock(self, **_kwargs: Any) -> None:
        """Lock the lock."""
        self._set_pending(True)
        datapoint = self._device.datapoints.get_or_create(
            self._mapping.manual_lock_dp_id,
            TuyaBLEDataPointType.DT_BOOL,
            True,
        )
        try:
            await datapoint.set_value(True)
        except Exception as err:
            self._set_pending(None)
            raise HomeAssistantError(f"Failed to send lock command: {err}") from err

    async def async_unlock(self, **_kwargs: Any) -> None:
        """Unlock the lock with a freshly registered one-time code."""
        self._set_pending(False)
        code = f"{secrets.randbelow(10**8):08d}"
        member_id = self._mapping.code_member_id
        try:
            result = await self._send_raw_and_wait_reply(
                self._mapping.set_code_dp_id,
                build_set_code_payload(code, member_id, int(time.time())),
            )
            if result is None:
                _LOGGER.debug(
                    "%s: No reply to one-time code registration, unlocking anyway",
                    self._device.address,
                )
            elif result != 0:
                msg = (
                    "Lock rejected the one-time code: "
                    f"{CODE_RESULTS.get(result, f'error {result}')}"
                )
                raise HomeAssistantError(msg)

            result = await self._send_raw_and_wait_reply(
                self._mapping.unlock_code_dp_id,
                build_code_unlock_payload(code, member_id),
            )
            if result is not None and result != 0:
                msg = f"Unlock failed: {CODE_RESULTS.get(result, f'error {result}')}"
                raise HomeAssistantError(msg)
        except HomeAssistantError:
            self._set_pending(None)
            raise
        except Exception as err:
            self._set_pending(None)
            raise HomeAssistantError(f"Failed to send unlock command: {err}") from err

    async def _send_raw_and_wait_reply(self, dp_id: int, value: bytes) -> int | None:
        """Send a raw datapoint and return the result byte the lock replies with."""
        future: asyncio.Future[int] = self.hass.loop.create_future()
        self._reply_waiters[dp_id] = future
        try:
            datapoint = self._device.datapoints.get_or_create(
                dp_id,
                TuyaBLEDataPointType.DT_RAW,
                value,
            )
            await datapoint.set_value(value)
            async with asyncio.timeout(REPLY_TIMEOUT):
                return await future
        except TimeoutError:
            return None
        finally:
            self._reply_waiters.pop(dp_id, None)

    @callback
    def _set_pending(self, locking: bool | None) -> None:
        """Show a transitional state until the lock reports the new state."""
        if self._unsub_pending is not None:
            self._unsub_pending()
            self._unsub_pending = None
        self._pending = locking
        if locking is not None:
            self._unsub_pending = async_call_later(
                self.hass, PENDING_TIMEOUT, self._pending_timeout
            )
        self.async_write_ha_state()

    @callback
    def _pending_timeout(self, _now: datetime) -> None:
        """Stop showing locking/unlocking when the lock did not report back."""
        self._unsub_pending = None
        if self._pending is not None:
            _LOGGER.debug(
                "%s: Lock state did not change after command", self._device.address
            )
            self._set_pending(None)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        for dp_id, future in self._reply_waiters.items():
            datapoint = self._device.datapoints[dp_id]
            if (
                not future.done()
                and datapoint
                and datapoint.changed_by_device
                and isinstance(datapoint.value, bytes)
                and datapoint.value
            ):
                future.set_result(datapoint.value[0])

        if self._pending is not None and self.is_locked is self._pending:
            self._set_pending(None)
        else:
            self.async_write_ha_state()

    async def async_will_remove_from_hass(self) -> None:
        """Cancel the pending state timer."""
        if self._unsub_pending is not None:
            self._unsub_pending()
            self._unsub_pending = None
        await super().async_will_remove_from_hass()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Tuya BLE lock platform."""
    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    mappings = get_mapping_by_device(data.device)

    entities: list[TuyaBLELock | TuyaBLECodeLock] = [
        TuyaBLECodeLock(hass, data.coordinator, data.device, data.product, mapping)
        if isinstance(mapping, TuyaBLECodeLockMapping)
        else TuyaBLELock(hass, data.coordinator, data.device, data.product, mapping)
        for mapping in mappings
    ]

    async_add_entities(entities)
