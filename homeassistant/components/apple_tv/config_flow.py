"""Config flow for Apple TV integration."""
import logging

import voluptuous as vol

from homeassistant import core, config_entries, exceptions
from homeassistant.const import CONF_NAME, CONF_DEVICE_ID, CONF_PROTOCOL
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

DATA_SCHEMA = vol.Schema({"device_id": str})


class AppleTVConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Apple TV."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_LOCAL_PUSH

    def __init__(self):
        self._atv = None
        self._device_id = None
        self._protocol = None

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        if user_input is not None:
            try:
                self._device_id = user_input["device_id"]
                return await self.async_step_find_device()
            except DeviceNotFound:
                errors["base"] = "device_not_found"
            except NoUsableService:
                errors["base"] = "no_usable_service"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user", data_schema=DATA_SCHEMA, errors=errors
        )

    async def async_step_find_device(self, user_input=None):
        """Ha"dle initial step."""
        from pyatv import const, scan_for_apple_tvs

        for entry in self._async_current_entries():
            if entry.data[CONF_DEVICE_ID] == self._device_id:
                return self.async_abort(reason="already_configured")

        atvs = await scan_for_apple_tvs(
            self.hass.loop, timeout=3, device_id=self._device_id
        )
        if not atvs:
            raise DeviceNotFound()

        self._atv = atvs[0]
        if self._atv.get_service(const.PROTOCOL_MRP) is not None:
            self._protocol = const.PROTOCOL_MRP
        elif self._atv.get_service(const.PROTOCOL_DMAP) is not None:
            self._protocol = const.PROTOCOL_DMAP

        if self._protocol is None:
            raise NoUsableService()

        return await self.async_step_confirm()

    async def async_step_zeroconf(self, discovery_info):
        from pyatv import get_device_id

        self._device_id = await get_device_id(discovery_info["host"], self.hass.loop)
        if not self._device_id:
            return self.async_abort(reason="lookup_id_failed")

        return await self.async_step_find_device()

    async def async_step_confirm(self, user_input=None):
        """Handle user-confirmation of discovered node."""
        if user_input is not None:
            return self._async_get_entry()
        return self.async_show_form(
            step_id="confirm", description_placeholders={"name": self._atv.name}
        )

    def _async_get_entry(self):
        return self.async_create_entry(
            title=self._atv.name,
            data={
                CONF_DEVICE_ID: self._atv.device_id,
                CONF_NAME: self._atv.name,
                CONF_PROTOCOL: self._protocol,
            },
        )


class DeviceNotFound(exceptions.HomeAssistantError):
    """Error to indicate device could not be found."""


class NoUsableService(exceptions.HomeAssistantError):
    """Error to indicate no usable service."""
