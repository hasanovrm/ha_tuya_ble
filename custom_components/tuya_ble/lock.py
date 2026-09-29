"""The Tuya BLE lock integration."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from struct import pack
from typing import TYPE_CHECKING, Any

import voluptuous as vol
from homeassistant.components.lock import (
    LockEntity,
    LockEntityDescription,
)
from homeassistant.core import (
    CALLBACK_TYPE,
    HomeAssistant,
    ServiceResponse,
    SupportsResponse,
    callback,
)
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_platform
from homeassistant.helpers.event import async_call_later
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .devices import TuyaBLECoordinator, TuyaBLEData, TuyaBLEEntity, TuyaBLEProductInfo
from .tuya_ble import TuyaBLEDataPointType, TuyaBLEDevice

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .tuya_ble import TuyaBLEDataPoint

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

# Unlocking method management (Tuya BLE lock DP reference). This lock answers
# without the 2 byte cloud unique ID from the reference, so commands omit it.
# unlock_method_create (DP 1): type, stage, admin, member, hardware ID,
#   validity period (17), times, password length, password
#   reply: type, stage, admin, member, hardware ID, times, result
# unlock_method_delete (DP 2): type, stage, admin, member, hardware ID, method
#   reply: the same fields followed by the result
# temporary_password_creat (DP 51): type, validity period (17), times,
#   password length, password; reply: hardware ID, result
# temporary_password_delete (DP 52): hardware ID; reply: hardware ID, result
# synch_method (DP 54): method type; replies: stage 0, packet number, entries
#   of (hardware ID, method type, flags, member) and finally stage 1, count
METHOD_PASSWORD = 0x01
METHOD_FINGERPRINT = 0x03
METHOD_NAMES = {
    0x01: "password",
    0x02: "card",
    0x03: "fingerprint",
    0x04: "face",
}
STAGE_START = 0x00
STAGE_PROGRESS = 0xFC
STAGE_FAILED = 0xFD
STAGE_CANCELED = 0xFE
DELETE_ONE_METHOD = 0x01
DELETE_SUCCESS = 0xFF
DELETE_RESULTS = {
    0x00: "deletion failed",
    0x01: "unlocking method does not exist",
}
TEMP_PASSWORD_TYPE = 0x00
TEMP_PASSWORD_RESULTS = {
    0x01: "failure",
    0x02: "no free slot",
    0x03: "repeated password",
}
TEMP_DELETE_RESULTS = {
    0x01: "failure",
    0x02: "password does not exist",
}
SYNC_STAGE_DATA = 0x00
SYNC_STAGE_DONE = 0x01
SYNC_ENTRY_SIZE = 4
# End of the validity period of permanent passwords, kept below 2^31
PERMANENT_END = 2145916799  # 2037-12-31 23:59:59 UTC
# Permanent passwords start a day early so a lagging lock clock accepts them
PERMANENT_START_SKEW = 86400

# Seconds to wait for the lock to answer a raw command
REPLY_TIMEOUT = 5
# Seconds to wait for all packets of a stored unlocking methods listing
SYNC_TIMEOUT = 10
# Seconds to wait for the lock to report itself open after an unlock
OPEN_TIMEOUT = 15
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


def build_validity(start: int, end: int) -> bytes:
    """Build a validity period without recurrence, valid all day."""
    # start, end, recurrence, month days, weekdays, daily 00:00 - 23:59
    return pack(">IIB3sBBBBB", start, end, 0, bytes(3), 0, 0, 0, 23, 59)


def build_add_password_payload(
    code: str,
    member_id: int,
    hardware_id: int,
    admin: bool,
    start: int,
    end: int,
    times: int,
) -> bytes:
    """Build an unlock_method_create value adding a password."""
    password = code.encode("ascii")
    return (
        bytes([METHOD_PASSWORD, STAGE_START, int(admin), member_id, hardware_id])
        + build_validity(start, end)
        + bytes([times, len(password)])
        + password
    )


def build_delete_method_payload(
    method: int, member_id: int, hardware_id: int, admin: bool
) -> bytes:
    """Build an unlock_method_delete value removing one unlocking method."""
    return bytes(
        [DELETE_ONE_METHOD, STAGE_START, int(admin), member_id, hardware_id, method]
    )


def build_add_temporary_password_payload(
    code: str, start: int, end: int, times: int
) -> bytes:
    """Build a temporary_password_creat value."""
    password = code.encode("ascii")
    return (
        bytes([TEMP_PASSWORD_TYPE])
        + build_validity(start, end)
        + bytes([times, len(password)])
        + password
    )


def parse_sync_entries(data: bytes) -> list[dict[str, Any]]:
    """Parse the unlocking methods listed in a synch_method data packet."""
    return [
        {
            "hardware_id": data[pos],
            "type": METHOD_NAMES.get(data[pos + 1], data[pos + 1]),
            "member_id": data[pos + 3],
            "flags": data[pos + 2],
        }
        for pos in range(0, len(data) - SYNC_ENTRY_SIZE + 1, SYNC_ENTRY_SIZE)
    ]


def _first_byte(replies: list[bytes]) -> int | None:
    """Return the result byte of the first reply, if any."""
    if replies and replies[0]:
        return replies[0][0]
    return None


def _timestamp(value: datetime) -> int:
    """Convert a service datetime (naive means local time) to a UNIX timestamp."""
    return int(dt_util.as_timestamp(value))


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
    add_method_dp_id: int = 1  # unlock_method_create
    delete_method_dp_id: int = 2  # unlock_method_delete
    add_temp_password_dp_id: int = 51  # temporary_password_creat
    delete_temp_password_dp_id: int = 52  # temporary_password_delete
    sync_dp_id: int = 54  # synch_method
    auto_lock_dp_id: int = 33  # auto_locking, missing from the cloud schema
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

_CODE = vol.All(cv.string, vol.Match(r"^\d{6,10}$"))
_MEMBER_ID = vol.All(vol.Coerce(int), vol.Range(min=1, max=100))
_HARDWARE_ID = vol.All(vol.Coerce(int), vol.Range(min=0, max=254))
_TIMES = vol.All(vol.Coerce(int), vol.Range(min=0, max=254))

SERVICES: list[tuple[str, dict, str, SupportsResponse]] = [
    (
        "add_password",
        {
            vol.Required("code"): _CODE,
            vol.Optional("member_id", default=1): _MEMBER_ID,
            vol.Optional("admin", default=False): cv.boolean,
            vol.Optional("start"): cv.datetime,
            vol.Optional("end"): cv.datetime,
            vol.Optional("times", default=0): _TIMES,
        },
        "async_add_password",
        SupportsResponse.OPTIONAL,
    ),
    (
        "delete_password",
        {
            vol.Required("hardware_id"): _HARDWARE_ID,
            vol.Optional("member_id", default=1): _MEMBER_ID,
            vol.Optional("admin", default=False): cv.boolean,
        },
        "async_delete_password",
        SupportsResponse.NONE,
    ),
    (
        "add_temporary_password",
        {
            vol.Required("code"): _CODE,
            vol.Required("start"): cv.datetime,
            vol.Required("end"): cv.datetime,
            vol.Optional("times", default=0): _TIMES,
        },
        "async_add_temporary_password",
        SupportsResponse.OPTIONAL,
    ),
    (
        "delete_temporary_password",
        {vol.Required("hardware_id"): _HARDWARE_ID},
        "async_delete_temporary_password",
        SupportsResponse.NONE,
    ),
    (
        "unlock_and_hold",
        {
            vol.Optional("retries", default=3): vol.All(
                vol.Coerce(int), vol.Range(min=1, max=10)
            )
        },
        "async_unlock_and_hold",
        SupportsResponse.OPTIONAL,
    ),
    (
        "lock_and_auto_lock",
        {
            vol.Optional("retries", default=3): vol.All(
                vol.Coerce(int), vol.Range(min=1, max=10)
            )
        },
        "async_lock_and_auto_lock",
        SupportsResponse.OPTIONAL,
    ),
    (
        "get_unlock_methods",
        {},
        "async_get_unlock_methods",
        SupportsResponse.ONLY,
    ),
]


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
        # Raw values the lock reports, per datapoint a command waits on
        self._reply_queues: dict[int, asyncio.Queue[bytes]] = {}
        # One command exchange with the lock at a time
        self._command_lock = asyncio.Lock()

    async def async_added_to_hass(self) -> None:
        """Listen to raw datapoint reports to collect command replies."""
        await super().async_added_to_hass()
        self.async_on_remove(self._device.register_callback(self._handle_datapoints))

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
            async with self._command_lock:
                await datapoint.set_value(True)
        except Exception as err:
            self._set_pending(None)
            raise HomeAssistantError(f"Failed to send lock command: {err}") from err

    async def async_unlock(self, **_kwargs: Any) -> None:
        """Unlock the lock with a freshly registered one-time code."""
        self._set_pending(False)
        try:
            async with self._command_lock:
                await self._unlock_with_code()
        except HomeAssistantError:
            self._set_pending(None)
            raise
        except Exception as err:
            self._set_pending(None)
            raise HomeAssistantError(f"Failed to send unlock command: {err}") from err

    async def async_unlock_and_hold(self, retries: int) -> ServiceResponse:
        """Switch auto locking off and unlock, so the lock stays open.

        Each step is checked against what the lock reports and the whole
        sequence is retried, which matters when a safety automation calls it.
        """
        self._set_pending(False)
        errors: list[str] = []
        auto_lock_off = False
        opened = False
        for attempt in range(1, retries + 1):
            try:
                async with self._command_lock:
                    reported = await self._write_bool_and_wait(
                        self._mapping.auto_lock_dp_id, False
                    )
                    auto_lock_off = reported is False
                    await self._unlock_with_code()
                    opened = await self._wait_for_lock_state(unlocked=True)
            except Exception as err:
                errors.append(f"attempt {attempt}: {err}")
                continue
            if opened:
                self._set_pending(None)
                return {
                    "opened": True,
                    "attempts": attempt,
                    "auto_lock_off_confirmed": auto_lock_off,
                }
            errors.append(f"attempt {attempt}: the lock did not report itself open")
        self._set_pending(None)
        raise HomeAssistantError("Could not unlock and hold: " + "; ".join(errors))

    async def async_lock_and_auto_lock(self, retries: int) -> ServiceResponse:
        """Switch auto locking back on and lock, the reverse of unlock and hold."""
        self._set_pending(True)
        errors: list[str] = []
        auto_lock_on = False
        locked = False
        for attempt in range(1, retries + 1):
            try:
                async with self._command_lock:
                    reported = await self._write_bool_and_wait(
                        self._mapping.auto_lock_dp_id, True
                    )
                    auto_lock_on = reported is True
                    await self._write_bool_and_wait(
                        self._mapping.manual_lock_dp_id, True
                    )
                    locked = await self._wait_for_lock_state(unlocked=False)
            except Exception as err:
                errors.append(f"attempt {attempt}: {err}")
                continue
            if locked:
                self._set_pending(None)
                return {
                    "locked": True,
                    "attempts": attempt,
                    "auto_lock_on_confirmed": auto_lock_on,
                }
            errors.append(f"attempt {attempt}: the lock did not report itself locked")
        self._set_pending(None)
        raise HomeAssistantError(
            "Could not lock and switch auto locking on: " + "; ".join(errors)
        )

    async def _unlock_with_code(self) -> None:
        """Register a one-time code and unlock with it."""
        code = f"{secrets.randbelow(10**8):08d}"
        member_id = self._mapping.code_member_id
        result = _first_byte(
            await self._request(
                self._mapping.set_code_dp_id,
                build_set_code_payload(code, member_id, int(time.time())),
            )
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

        result = _first_byte(
            await self._request(
                self._mapping.unlock_code_dp_id,
                build_code_unlock_payload(code, member_id),
            )
        )
        if result is not None and result != 0:
            msg = f"Unlock failed: {CODE_RESULTS.get(result, f'error {result}')}"
            raise HomeAssistantError(msg)

    async def _write_bool_and_wait(
        self, dp_id: int, value: bool, timeout: float = REPLY_TIMEOUT
    ) -> bool | None:
        """Write a boolean datapoint and return what the lock reports back."""
        queue: asyncio.Queue[Any] = asyncio.Queue()
        self._reply_queues[dp_id] = queue
        try:
            datapoint = self._device.datapoints.get_or_create(
                dp_id,
                TuyaBLEDataPointType.DT_BOOL,
                value,
            )
            await datapoint.set_value(value)
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(timeout):
                    return bool(await queue.get())
        finally:
            self._reply_queues.pop(dp_id, None)
        return None

    async def _wait_for_lock_state(
        self, *, unlocked: bool, timeout: float = OPEN_TIMEOUT
    ) -> bool:
        """Wait until the lock reports itself unlocked, or locked."""
        if self.is_locked is (not unlocked):
            return True
        queue: asyncio.Queue[Any] = asyncio.Queue()
        self._reply_queues[self._mapping.state_dp_id] = queue
        try:
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(timeout):
                    while True:
                        # lock_motor_state is true when the lock is open
                        if bool(await queue.get()) is unlocked:
                            return True
        finally:
            self._reply_queues.pop(self._mapping.state_dp_id, None)
        return False

    async def async_add_password(
        self,
        code: str,
        member_id: int,
        admin: bool,
        times: int,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> ServiceResponse:
        """Add a permanent password, returning the slot the lock stored it in."""
        start_ts = (
            _timestamp(start) if start else int(time.time()) - PERMANENT_START_SKEW
        )
        end_ts = _timestamp(end) if end else PERMANENT_END
        if end_ts <= start_ts:
            raise ServiceValidationError("The end must be after the start")

        async with self._command_lock:
            # Ask for a free slot so an existing password can never be replaced,
            # whether the lock honors the requested slot or picks one itself
            used = {
                method["hardware_id"]
                for method in await self._sync_methods(METHOD_PASSWORD)
            }
            hardware_id = next((i for i in range(1, 0xFF) if i not in used), None)
            if hardware_id is None:
                raise HomeAssistantError("The lock has no free password slot")
            replies = await self._request(
                self._mapping.add_method_dp_id,
                build_add_password_payload(
                    code, member_id, hardware_id, admin, start_ts, end_ts, times
                ),
                until=lambda reply: len(reply) > 1 and reply[1] != STAGE_PROGRESS,
            )

        if not replies:
            raise HomeAssistantError("The lock did not answer the add password request")
        reply = replies[-1]
        if (
            len(reply) < 7
            or reply[1] in (STAGE_FAILED, STAGE_CANCELED)
            or reply[6] not in (0x00, 0xFF)
        ):
            msg = f"The lock rejected the password (reply {reply.hex(' ')})"
            raise HomeAssistantError(msg)
        return {"hardware_id": reply[4], "member_id": reply[3]}

    async def async_delete_password(
        self, hardware_id: int, member_id: int, admin: bool
    ) -> None:
        """Delete a password by the slot it is stored in."""
        async with self._command_lock:
            replies = await self._request(
                self._mapping.delete_method_dp_id,
                build_delete_method_payload(
                    METHOD_PASSWORD, member_id, hardware_id, admin
                ),
            )
        if not replies or not replies[0]:
            raise HomeAssistantError("The lock did not answer the delete request")
        result = replies[0][-1]
        if result != DELETE_SUCCESS:
            msg = (
                "Deleting the password failed: "
                f"{DELETE_RESULTS.get(result, f'error {result}')}"
            )
            raise HomeAssistantError(msg)

    async def async_add_temporary_password(
        self, code: str, start: datetime, end: datetime, times: int
    ) -> ServiceResponse:
        """Add a password valid between start and end, returning its slot."""
        start_ts = _timestamp(start)
        end_ts = _timestamp(end)
        if end_ts <= start_ts:
            raise ServiceValidationError("The end must be after the start")

        async with self._command_lock:
            replies = await self._request(
                self._mapping.add_temp_password_dp_id,
                build_add_temporary_password_payload(code, start_ts, end_ts, times),
            )
        if not replies or len(replies[0]) < 2:
            raise HomeAssistantError(
                "The lock did not answer the add temporary password request"
            )
        hardware_id, result = replies[0][0], replies[0][1]
        if result != 0:
            msg = (
                "The lock rejected the temporary password: "
                f"{TEMP_PASSWORD_RESULTS.get(result, f'error {result}')}"
            )
            raise HomeAssistantError(msg)
        return {"hardware_id": hardware_id}

    async def async_delete_temporary_password(self, hardware_id: int) -> None:
        """Delete a temporary password by its slot."""
        async with self._command_lock:
            replies = await self._request(
                self._mapping.delete_temp_password_dp_id, bytes([hardware_id])
            )
        if not replies or len(replies[0]) < 2:
            raise HomeAssistantError("The lock did not answer the delete request")
        result = replies[0][1]
        if result not in (0x00, 0xFF):
            msg = (
                "Deleting the temporary password failed: "
                f"{TEMP_DELETE_RESULTS.get(result, f'error {result}')}"
            )
            raise HomeAssistantError(msg)

    async def async_get_unlock_methods(self) -> ServiceResponse:
        """List the passwords and fingerprints stored in the lock."""
        async with self._command_lock:
            methods = [
                *await self._sync_methods(METHOD_PASSWORD),
                *await self._sync_methods(METHOD_FINGERPRINT),
            ]
        return {"methods": methods}

    async def _sync_methods(self, method: int) -> list[dict[str, Any]]:
        """Read the unlocking methods of one type stored in the lock."""
        replies = await self._request(
            self._mapping.sync_dp_id,
            bytes([method]),
            until=lambda reply: bool(reply) and reply[0] == SYNC_STAGE_DONE,
            timeout=SYNC_TIMEOUT,
        )
        methods: list[dict[str, Any]] = []
        for reply in replies:
            if len(reply) > 2 and reply[0] == SYNC_STAGE_DATA:
                methods.extend(parse_sync_entries(reply[2:]))
        return methods

    async def _request(
        self,
        dp_id: int,
        value: bytes,
        until: Callable[[bytes], bool] | None = None,
        timeout: float = REPLY_TIMEOUT,
    ) -> list[bytes]:
        """Send a raw datapoint and collect the values the lock replies with.

        Collecting stops at the first reply for which `until` is true (the
        first reply when not given) or when the timeout expires.
        """
        queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._reply_queues[dp_id] = queue
        replies: list[bytes] = []
        try:
            datapoint = self._device.datapoints.get_or_create(
                dp_id,
                TuyaBLEDataPointType.DT_RAW,
                value,
            )
            await datapoint.set_value(value)
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(timeout):
                    while True:
                        reply = await queue.get()
                        if not isinstance(reply, bytes):
                            continue
                        replies.append(reply)
                        if until is None or until(reply):
                            break
        finally:
            self._reply_queues.pop(dp_id, None)
        _LOGGER.debug(
            "%s: Replies to datapoint %s: %s",
            self._device.address,
            dp_id,
            [reply.hex(" ") for reply in replies],
        )
        return replies

    @callback
    def _handle_datapoints(self, datapoints: list[TuyaBLEDataPoint]) -> None:
        """Pass values reported by the lock to a command waiting on them."""
        for datapoint in datapoints:
            queue = self._reply_queues.get(datapoint.id)
            if queue is not None:
                value = datapoint.value
                queue.put_nowait(bytes(value) if isinstance(value, bytes) else value)

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

    # The button platform runs the unlock and hold sequence on this entity
    data.code_lock = next(
        (entity for entity in entities if isinstance(entity, TuyaBLECodeLock)), None
    )

    if data.code_lock is not None:
        platform = entity_platform.async_get_current_platform()
        for name, schema, method, supports_response in SERVICES:
            platform.async_register_entity_service(
                name, schema, method, supports_response=supports_response
            )
