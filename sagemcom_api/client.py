"""Client to communicate with Sagemcom F@st internal APIs."""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import random
from types import TracebackType
from typing import Dict, List, Optional, Type

from aiohttp import ClientSession, ClientTimeout
import humps
from urllib.parse import quote

from . import __version__
from .const import (
    API_ENDPOINT,
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    XMO_ACCESS_RESTRICTION_ERR,
    XMO_AUTHENTICATION_ERR,
    XMO_NO_ERR,
    XMO_NON_WRITABLE_PARAMETER_ERR,
    XMO_REQUEST_ACTION_ERR,
    XMO_REQUEST_NO_ERR,
    XMO_UNKNOWN_PATH_ERR,
)
from .enums import EncryptionMethod, ActionMethod
from .exceptions import (
    AccessRestrictionException,
    AuthenticationException,
    BadRequestException,
    LoginTimeoutException,
    NonWritableParameterException,
    UnauthorizedException,
    UnknownException,
    UnknownPathException,
)
from .models import Device, DeviceInfo, PortMapping, Parental_Control_Rule, TimeSlotList, MacAddressList, Parental_Control_Config, Functionalities, Usage_Entry_List
from .utils import epoch

class SagemcomClient:
    """Client to communicate with the Sagemcom API."""

    def __init__(
        self,
        host,
        username,
        password,
        authentication_method,
        session: ClientSession = None,
    ):
        """
        Create a SagemCom client.

        :param host: the host of your Sagemcom router
        :param username: the username for your Sagemcom router
        :param password: the password for your Sagemcom router
        :param authentication_method: the auth method of your Sagemcom router
        :param session: use a custom session, for example to configure the timeout
        """
        self.host = host
        self.username = username
        self.authentication_method = authentication_method
        self._password_hash = self.__generate_hash(password)

        self._current_nonce = None
        self._server_nonce = ""
        self._session_id = 0
        self._request_id = -1

        self.session = (
            session
            if session
            else ClientSession(
                headers={"User-Agent": f"{DEFAULT_USER_AGENT}/{__version__}"},
                timeout=ClientTimeout(DEFAULT_TIMEOUT),
            )
        )

    async def __aenter__(self) -> SagemcomClient:
        """TODO."""
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """Close session on exit."""
        await self.close()

    async def close(self) -> None:
        """Close the websession."""
        await self.session.close()

    def __generate_nonce(self):
        """Generate pseudo random number (nonce) to avoid replay attacks."""
        self._current_nonce = math.floor(random.randrange(0, 1) * 500000)

    def __generate_request_id(self):
        """Generate sequential request ID."""
        self._request_id += 1

    def __generate_hash(self, value, authentication_method=None):
        """Hash value with selected encryption method and return HEX value."""
        auth_method = authentication_method or self.authentication_method

        bytes_object = bytes(value, encoding="utf-8")

        if auth_method == EncryptionMethod.MD5:
            return hashlib.md5(bytes_object).hexdigest()

        if auth_method == EncryptionMethod.SHA512:
            return hashlib.sha512(bytes_object).hexdigest()

        return value

    def __get_credential_hash(self):
        """Build credential hash."""
        return self.__generate_hash(
            self.username + ":" + self._server_nonce + ":" + self._password_hash
        )

    def __generate_auth_key(self):
        """Build auth key."""
        credential_hash = self.__get_credential_hash()
        auth_string = f"{credential_hash}:{self._request_id}:{self._current_nonce}:JSON:{API_ENDPOINT}"
        self._auth_key = self.__generate_hash(auth_string)

    def __get_response_error(self, response):
        """Retrieve response error from result."""
        try:
            value = response["reply"]["error"]
        except KeyError:
            value = None

        return value

    def __get_response(self, response, index=0):
        """Retrieve response from result."""
        try:
            value = response["reply"]["actions"][index]["callbacks"][index][
                "parameters"
            ]
        except KeyError:
            value = None

        return value

    def __get_response_xpath(self, response, index=0):
        try:
            xpath = response["reply"]["actions"][index]["callbacks"][index]["xpath"]
        except KeyError:
            xpath = None

        return xpath

    def __get_response_value(self, response, index=0):
        """Retrieve response value from value."""
        try:
            value = self.__get_response(response, index)["value"]
        except KeyError:
            value = None

        # Rewrite result to snake_case
        value = humps.decamelize(value)

        return value

    def __get_response_capability(self, response, index=0):
        """Try to retrieve the capability from a response, maybe we can learn more from this?"""

        try:
            capability = self.__get_response(response, index)["capability"]
        except KeyError:
            capability = None

        # Rewrite result to snake_case
        capability = humps.decamelize(capability)

        return capability

    def __get_response_data(self, response, index=0):
        """Try to retrieve the data from a response, maybe we can learn more from this?"""

        try:
            data = self.__get_response(response, index)["data"]
        except KeyError:
            data = None

        return data

    async def __get_request_async(self, url_path: str):
                
        url = f"http://{self.host}{url_path}"
        print(url)

        async with self.session.get(
            url
        ) as response:

            if response.status == 400:
                result = await response.text()
                raise BadRequestException(result)

            if response.status != 200:
                result = await response.text()
                raise UnknownException(result)

            if response.status == 200:
                return await response.read()

    async def __api_request_async(self, actions, priority=False):
        """Build request to the internal JSON-req API."""
        # Auto login
        if self._server_nonce == "" and actions[0]["method"] != "logIn":
            await self.login()

        self.__generate_request_id()
        self.__generate_nonce()
        self.__generate_auth_key()

        api_host = f"http://{self.host}{API_ENDPOINT}"

        payload = {
            "request": {
                "id": self._request_id,
                "session-id": str(self._session_id),
                "priority": priority,
                "actions": actions,
                "cnonce": self._current_nonce,
                "auth-key": self._auth_key,
            }
        }

        async with self.session.post(
            api_host, data="req=" + quote(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        ) as response:

            if response.status == 400:
                result = await response.text()
                raise BadRequestException(result)

            if response.status != 200:
                result = await response.text()
                raise UnknownException(result)

            if response.status == 200:
                result = await response.json()
                error = self.__get_response_error(result)

                # No errors
                if (
                    error["description"] == XMO_REQUEST_NO_ERR
                    or error["description"] == "Ok"  # NOQA: W503
                ):
                    return result

                # Error in one of the actions
                if error["description"] == XMO_REQUEST_ACTION_ERR:

                    # TODO How to support multiple actions + error handling?
                    actions = result["reply"]["actions"]
                    for action in actions:
                        action_error = action["error"]
                        action_error_description = action_error["description"]

                        if action_error_description == XMO_NO_ERR:
                            continue

                        if action_error_description == XMO_AUTHENTICATION_ERR:
                            raise AuthenticationException(action_error)

                        if action_error_description == XMO_ACCESS_RESTRICTION_ERR:
                            raise AccessRestrictionException(action_error)

                        if action_error_description == XMO_NON_WRITABLE_PARAMETER_ERR:
                            raise NonWritableParameterException(action_error)

                        if action_error_description == XMO_UNKNOWN_PATH_ERR:
                            raise UnknownPathException(action_error)

                        raise UnknownException(action_error)

                return result

    async def login(self):
        """TODO."""
        actions = {
            "method": "logIn",
            "parameters": {
                "user": self.username,
                "persistent": True,
                "session-options": {
                    "nss": [{"name": "gtw", "uri": "http://sagemcom.com/gateway-data"}],
                    "language": "ident",
                    "context-flags": {"get-content-name": True, "local-time": True},
                    "capability-depth": 2,
                    "capability-flags": {
                        "name": True,
                        "default-value": False,
                        "restriction": True,
                        "description": False,
                    },
                    "time-format": "ISO_8601",
                    "write-only-string": "_XMO_WRITE_ONLY_",
                    "undefined-write-only-string": "_XMO_UNDEFINED_WRITE_ONLY_",
                },
            },
        }

        try:
            response = await self.__api_request_async([actions], True)
        except asyncio.TimeoutError as exception:
            raise LoginTimeoutException(
                "Request timed-out. This is mainly due to using the wrong encryption method."
            ) from exception

        data = self.__get_response(response)

        if data["id"] is not None and data["nonce"] is not None:
            self._session_id = data["id"]
            self._server_nonce = data["nonce"]
            return True
        else:
            raise UnauthorizedException(data)

    async def get_capability_by_xpath(
        self, xpath: str, options: Optional[Dict] = {}
    ) -> Dict:
        actions = self.build_action_for_request(ActionMethod.GETVALUE, xpath, "", options)

        response = await self.__api_request_async([actions], False)
        data = self.__get_response_capability(response)

        return data

    async def get_value_by_xpath(
        self, xpath: str, options: Optional[Dict] = {}
    ) -> Dict:
        """
        Retrieve raw value from router using XPath.

        :param xpath: path expression
        :param options: optional options
        """
        actions = self.build_action_for_request(ActionMethod.GETVALUE, xpath, "", options)

        response = await self.__api_request_async([actions], False)
        data = self.__get_response_value(response)

        return data

    async def set_value_by_xpath(
        self, xpath: str, value: str, options: Optional[Dict] = {}
    ) -> Dict:
        """
        Retrieve raw value from router using XPath.

        :param xpath: path expression
        :param value: value
        :param options: optional options
        """
        actions = self.build_action_for_request(ActionMethod.SETVALUE, xpath, value, options)

        response = await self.__api_request_async([actions], False)
        print(response)

        return response

    async def add_child_by_xpath(self, xpath):
        """
        Create a new child item to for an xpath.  Returns the xpath of the added child

        :param xpath: path expression
        :return uid: a unique identifier for the newly created child
        """
        action = self.build_action_for_request(ActionMethod.ADDCHILD, xpath)
        response = await self.__api_request_async([action], False)
        _xpath = self.__get__response_xpath(response)
        return _xpath

    async def multiple_actions_by_xpath(
        self, actions: list
    ) -> Dict:
        """
        
        """
        _actions = []
        id = 0

        for action in actions:
            action["id"] = id
            id += 1
            _actions.append(action)

        response = await self.__api_request_async(_actions, False)

        return response

    def build_action_for_request(
        self, method: str, xpath: str, value: Optional[str] = "", options: Optional[Dict] = {}
    ) -> Dict:
        """
        Prepares a single action for an API request

        :param xpath: path expression
        :param value: optional value
        :param options: optional options
        """

        if method in [ActionMethod.GETVALUE, ActionMethod.DELETECHILD]:
            action = {
                "id": 0,
                "method": method.value,
                "xpath": xpath,
                "options": options,
            }
        elif method in [ActionMethod.SETVALUE, ActionMethod.ADDCHILD]:
            action = {
                "id": 0,
                "method": method.value,
                "xpath": xpath,
                "parameters": {"value": str(value)},
                "options": options,
            }
        else:
            raise NotImplementedError

        return action
            

    async def get_device_info(self) -> DeviceInfo:
        """Retrieve information about Sagemcom F@st device."""
        data = await self.get_value_by_xpath("Device/DeviceInfo")

        return DeviceInfo(**data.get("device_info"))

    async def get_user_functionalities(self, user_uid) -> Functionalities:
        """Retrieve all functionalities enabled on device for the user"""
        try:
            data = await self.get_value_by_xpath("Device/UserAccounts/Users/User[@uid='" + str(user_uid) + "']/Functionalities")
        except UnknownPathException:
            data = None
            return "Unable to find functionalities for user_uid " + str(user_uid)

        result = {
            'user_uid': int(user_uid),
            'functionalities': data,
            }

        return Functionalities(**result)

    async def get_hosts(self, only_active: Optional[bool] = False) -> List[Device]:
        """Retrieve hosts connected to Sagemcom F@st device."""
        data = await self.get_value_by_xpath("Device/Hosts/Hosts")
        devices = [Device(**d) for d in data]

        if only_active:
            active_devices = [d for d in devices if d.active is True]
            return active_devices

        return devices


    async def get_port_mappings(self) -> List[PortMapping]:
        """Retrieve configured Port Mappings on Sagemcom F@st device."""
        data = await self.get_value_by_xpath("Device/NAT/PortMappings")
        port_mappings = [PortMapping(**p) for p in data]

        return port_mappings


    async def get_parental_control_config(self) -> Parental_Control_Config:
        """Retrieve full Parental Configuration"""
        data = await self.get_value_by_xpath("Device/Services/ParentalControl")

        return Parental_Control_Config(**data.get('parental_control'))


    async def get_parental_control_rules(self, only_active: Optional[bool] = False) -> List[Parental_Control_Rule]:
        """
        Retrieve current rules in Parental Control configuration
        
        :param only_active: Returns only rules currently blocking access
        """
        data = await self.get_value_by_xpath("Device/Services/ParentalControl/Rules")
        rules = [Parental_Control_Rule(**r) for r in data]

        if only_active:
            active_rules = [r for r in rules if r.status == 'ACTIVE']
            return active_rules


        return rules


    async def get_parental_control_rule_by_uid(self, uid) -> Parental_Control_Rule:

        data = await self.get_value_by_xpath("Device/Services/ParentalControl/Rules/Ruel[@uid'" + str(uid) + "']")

        return Parental_Control_Rule(**data.get('rule'))


    async def get_parental_control_rule_by_name(self, name: str) -> Parental_Control_Rule:
        """
        Retrieve a single parental control rule by name
        
        :param name: name/alias of parental control rule
        """
        result = None

        rules = await self.get_parental_control_rules()
        for rule in rules:
            if rule.name == name:
                result = rule
        
        return result


    async def add_parental_control_rule(self, alias: str) -> Parental_Control_Rule:

        macaddresses_xpath = await self.add_child_by_xpath("Device/Services/ParentalControl/MACAddressLists")
        timeslots_xpath = await self.add_child_by_xpath("Device/Services/ParentalControl/TimeSlotLists")
        rule_xpath = await self.add_child_by_xpath("Device/Services/ParentalControl/Rules")
        
        actions = []
        new_rule_requirements = [
            ("/Enable", "true"), 
            ("/Alias", alias), 
            ("/TimeSlots", timeslots_xpath), 
            ("/WANAccess", "DROP"), 
            ("/MACAddresses", macaddresses_xpath)]

        for r in new_rule_requirements:
            actions.append(self.build_action_for_request(ActionMethod.SETVALUE.value, rule_xpath + r[0], r[1]))

        #TODO:mutiple actions... if response?...

        response = await self.multiple_actions_by_xpath(actions)
        data = await self.get_value_by_xpath(rule_xpath)

        return Parental_Control_Rule(**data.get('rule'))


    async def get_parental_control_rule_timeslots(self, rule_uid) -> TimeSlotList:
        """
        Retrieve time slots for a Parental Control rule
        
        :param rule_uid: uid of Parental Control Rule to get TimeSlotList
        """
        rule = await self.get_parental_control_rule_by_uid(rule_uid)
        data = await self.get_value_by_xpath(rule.time_slots)
        
        return TimeSlotList(**data.get('time_slot_list'))


    async def delete_parental_control_rule_timeslots(self, rule_uid):
        
        #TODO: delete all timeslots
        #TODO: delete list

        return


    async def get_parental_control_rule_macaddresses(self, rule_uid) -> MacAddressList:
        """
        Retieve mac addresse(s) targeted by a parental control rule
        
        :param rule_uid: uid of Parental Control Rule to get MacAddressList
        """
        rule = await self.get_parental_control_rule_by_uid(rule_uid)
        data = await self.get_value_by_xpath(rule.mac_addresses)

        return MacAddressList(**data.get('mac_address_list'))


    async def update_parental_control_rule_macaddresses(self, rule_uid, mac_addresses: str) -> MacAddressList:
        """
        Update mac addresse(s) targeted by a Parental Control rule

        :param rule_uid: uid of Parental Control Rule to get MacAddressList
        :param mac_adddreses: string of comma separated mac addresses

        """
        rule = await self.get_parental_control_rule_by_uid(rule_uid)
        xpath = rule.mac_addresses + "/MACAddresses"

        response = await self.set_value_by_xpath(xpath, mac_addresses)
        #TODO: update alias of mac list with new epoch
        mac_address_list = await self.get_parental_control_rule_macaddresses(rule.uid)

        return mac_address_list


    
    async def reboot(self):
        """Reboot Sagemcom F@st device."""
        action = {
            "method": "reboot",
            "xpath": "Device",
            "parameters": {"source": "GUI"},
        }

        response = await self.__api_request_async([action], False)
        data = self.__get_response_value(response)

        return data

    async def get_data_usage(self, start_date:str, end_date:str) -> Usage_Entry_List:
        """
        Retrieves the data usage by device for a date interval

        :param start_data: date string using format YYYYMMDD
        :param end_date: date string using format YYYYMMDD
        """
        action = {
            "method": "uploadBMStatisticsFile",
            "xpath": "Device",
            "parameters": {
                "startDate": start_date,
                "endDate": end_date

            }
        }

        response = await self.__api_request_async([action], False)

        csv_url = self.__get_response_data(response)
        csv_url = f"{csv_url}?_={epoch()}"
        
        csv_bytes = await self.__get_request_async(csv_url)

        import os
        import tempfile
        import csv

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            try:
                f.write(csv_bytes)
            finally:
                f.close()        
        
        try:
            with open(f.name) as tmpfile:
                reader = csv.DictReader(tmpfile, fieldnames=('modem', 'mac_address', 'date', 'download', 'upload', 'device_type'))
                entries = []
                for entry in map(dict, reader):
                    entries.append(entry)

        finally:
            os.unlink(f.name)
        
        entry_list = {
            'start_date': start_date,
            'end_date': end_date,
            'entries': entries
        }

        #print(entry_list)

        return Usage_Entry_List(**entry_list)



