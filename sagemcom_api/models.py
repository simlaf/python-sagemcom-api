"""Models for the Sagemcom F@st client."""

import dataclasses
from dataclasses import dataclass
from typing import Any, List, Optional
from .enums import Weekday
import time


@dataclass
class Device:
    """Device connected to a router."""

    uid: Optional[int] = None
    alias: Optional[str] = None
    phys_address: Optional[str] = None
    ip_address: Optional[str] = None
    address_source: Optional[str] = None
    dhcp_client: Optional[str] = None
    lease_time_remaining: Optional[int] = None
    associated_device: Optional[Any] = None
    layer1_interface: Optional[Any] = None
    layer3_interface: Optional[Any] = None
    vendor_class_id: Optional[Any] = None
    client_id: Optional[Any] = None
    user_class_id: Optional[Any] = None
    host_name: Optional[Any] = None
    active: Optional[bool] = None
    lease_start: Optional[int] = None
    lease_duration: Optional[int] = None
    interface_type: Optional[str] = None  # enum!
    detected_device_type: Optional[str] = None
    active_last_change: Optional[Any] = None
    user_friendly_name: Optional[str] = None
    user_host_name: Optional[str] = None
    user_device_type: Optional[Any] = None  # enum!
    icon: Optional[Any] = None
    room: Optional[Any] = None
    blacklist_enable: Optional[bool] = None
    blacklisted: Optional[bool] = None
    unblock_hours_count: Optional[int] = None
    blacklist_status: Optional[bool] = None
    blacklisted_according_to_schedule: Optional[bool] = None
    blacklisted_schedule: Optional[List] = None
    hidden: Optional[bool] = None
    options: Optional[List] = None
    vendor_class_idv6: Optional[Any] = None
    ipv4_addresses: Optional[List] = None
    ipv6_addresses: Optional[List] = None
    device_type_association: Optional[Any] = None

    # TODO Remove extra kwargs before init
    def __init__(self, **kwargs):
        """Override to accept more args than specified."""
        names = {f.name for f in dataclasses.fields(self)}
        for k, v in kwargs.items():
            if k in names:
                setattr(self, k, v)

    @property
    def id(self):
        """Return unique ID for device."""
        return self.phys_address.upper()

    @property
    def name(self):
        """Return name of the device."""
        return self.user_host_name or self.host_name


@dataclass
class DeviceInfo:
    """Sagemcom Router representation."""

    mac_address: str
    serial_number: Optional[str] = None
    manufacturer: Optional[Any] = None
    model_name: Optional[Any] = None
    model_number: Optional[Any] = None
    software_version: Optional[str] = None
    hardware_version: Optional[str] = None
    up_time: Optional[Any] = None
    reboot_count: Optional[Any] = None
    router_name: Optional[Any] = None
    bootloader_version: Optional[Any] = None
    device_category: Optional[Any] = None
    manufacturer_oui: Optional[Any] = None
    product_class: Optional[str] = None
    description: Optional[str] = None
    additional_hardware_version: Optional[str] = None
    additional_software_version: Optional[str] = None
    external_firmware_version: Optional[str] = None
    internal_firmware_version: Optional[str] = None
    gui_firmware_version: Optional[str] = None
    guiapi_version: Optional[float] = None
    provisioning_code: Optional[str] = None
    up_time: Optional[int] = None
    first_use_date: Optional[str] = None
    mac_address: Optional[str] = None
    mode: Optional[str] = None
    country: Optional[str] = None
    reboot_count: Optional[int] = None
    nodes_to_restore: Optional[str] = None
    router_name: Optional[str] = None
    reboot_status: Optional[float] = None
    reset_status: Optional[float] = None
    update_status: Optional[float] = None
    SNMP: Optional[bool] = None
    first_connection: Optional[bool] = None
    build_date: Optional[str] = None
    spec_version: Optional[str] = None
    CLID: Optional[str] = None
    flush_device_log: Optional[bool] = None
    locations: Optional[str] = None
    api_version: Optional[str] = None

    # TODO Remove extra kwargs before init
    def __init__(self, **kwargs):
        """Override to accept more args than specified."""
        names = {f.name for f in dataclasses.fields(self)}
        for k, v in kwargs.items():
            if k in names:
                setattr(self, k, v)

    @property
    def id(self):
        """Return unique ID for gateway."""
        return self.mac_address


@dataclass
class PortMapping:
    """Port Mapping representation."""

    uid: int
    enable: bool
    status: Optional[str] = None  # Enum
    alias: Optional[str] = None
    external_interface: Optional[str] = None
    all_external_interfaces: Optional[bool] = None
    lease_duration: Optional[int] = None
    external_port: Optional[int] = None
    external_port_end_range: Optional[int] = None
    internal_interface: Optional[str] = None
    internal_port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    internal_client: Optional[str] = None
    public_ip: Optional[str] = None
    description: Optional[str] = None
    creator: Optional[str] = None
    target: Optional[str] = None
    lease_start: Optional[str] = None  # Date?

    # TODO Remove extra kwargs before init
    def __init__(self, **kwargs):
        """Override to accept more args than specified."""
        names = {f.name for f in dataclasses.fields(self)}
        for k, v in kwargs.items():
            if k in names:
                setattr(self, k, v)

    @property
    def id(self):
        """Return unique ID for port mapping."""
        return self.uid

@dataclass
class Parental_Control_Rule:
    """Representation of a Parental Control Rule"""

    uid: int
    enable: bool
    status: Optional[str] = None  # Enum
    alias: Optional[str] = None
    priority: Optional[int] = None
    time_slots: Optional[str] = None #time_slot_list xpath
    wan_access: Optional[str] = None
    lan_access: Optional[str] = None
    restriction_access: Optional[str] = None
    restrictions: Optional[str] = None
    mac_addresses: Optional[str] = None #mac_address_list xpath

    def __init__(self, **kwargs):
        """Override to accept more args than specified."""
        names = {f.name for f in dataclasses.fields(self)}
        for k, v in kwargs.items():
            if k in names:
                setattr(self, k, v)

    @property
    def id(self):
        """Return unique ID for rule."""
        return self.uid

    @property
    def name(self):
        return self.alias

@dataclass
class TimeSlot:
    """Representation of a single time slot in a time slot list for Parental Control"""

    uid: int
    week_days: int
    start_time: int
    end_time: int

    @property
    def id(self):
        """Return unique ID for TimeSlot."""
        return self.uid

    @property
    def weekday(self):
        """Return weekday for time slot"""
        return Weekday(self.week_days).name

    @property
    def start(self):
        return time.strftime("%H:%M", time.gmtime(self.start_time))

    @property
    def end(self):
        return time.strftime("%H:%M", time.gmtime(self.end_time)) 


@dataclass
class TimeSlotList:
    """Representation of a list of TimeSlots for a single rule"""

    uid: int 
    alias: str #Rule alias followed by epoch of last modification
    always: bool
    time_slots: List[TimeSlot]

    @property
    def id(self):
        """Return ID for TimeSlotList associated with UID of Rule."""
        return self.uid

    @property
    def last_updated(self):
        epoch = int(self.alias[-13:])/1000
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch))


    def __post_init__(self):
        """Convert time_slots to List of TimeSlot"""
        slots = []
        for t in self.time_slots:
            slots.append(TimeSlot(**t))
        self.time_slots = slots


@dataclass
class MacAddressList:
    """Representation of a list of Mac Addresses impacted by a rule"""

    uid: int 
    alias: str #Rule alias followed by epoch of last modification
    all_devices: bool
    mac_addresses: Optional[str]

    @property
    def last_updated(self):
        epoch = int(self.alias[-13:])/1000
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch))

@dataclass
class Parental_Control_Config:
    """Parental Control Configuration"""

    enable: bool
    rules: List[Parental_Control_Rule]
    time_slot_lists: List[TimeSlotList]
    restriction_lists: List
    mac_address_lists: List[MacAddressList]

    def __post_init__(self):
        """Convert field lists to List of Classes"""
        _rules = []
        _time_slot_lists = []
        _mac_address_lists = []

        for r in self.rules:
            _rules.append(Parental_Control_Rule(**r))
        
        for t in self.time_slot_lists:
            _time_slot_lists.append(TimeSlotList(**t))

        for m in self.mac_address_lists:
            _mac_address_lists.append(MacAddressList(**m))
        
        self.rules = _rules
        self.time_slot_lists = _time_slot_lists
        self.mac_address_lists = _mac_address_lists

@dataclass
class Functionality:
    """A fonctionnality of Sagemcom device for the user"""

    uid: int
    name: str
    readable: bool
    writable: bool

@dataclass
class Functionalities:
    """All Fonctionalities listed for the user"""

    user_uid: int
    functionalities: List[Functionality]

    def get_readables(self):
        """Returns the name of the readable functionalities"""
        return [f.name for f in self.functionalities if f.readable == True]

    def get_writables(self):
        """Returns the name of the writeable functionalities"""
        return [f.name for f in self.functionalities if f.writable == True]

    def get_readonly(self):
        """Returns the name of functionalities that are readable but not writable"""
        return [f.name for f in self.functionalities if f.readable == True and f.writable == False]


    def __post_init__(self):
        
        funcs = []
        for f in self.functionalities:
            funcs.append(Functionality(**f))
        self.functionalities = funcs

@dataclass
class Usage_Entry():
    modem: str
    mac_address: str
    date: str
    download: int  #Probably GB?
    upload: int #Probably GB?
    device_type: str

    def __post_init__(self):
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if not isinstance(value, field.type):
                setattr(self, field.name, field.type(value))


@dataclass
class Usage_Entry_List():
    start_date: str
    end_date: str
    entries: List[Usage_Entry]

    def __post_init__(self):
        _entries = []

        for entry in self.entries:
            _entries.append(Usage_Entry(**entry))
        self.entries = _entries

    def get_total_download(self):
        return sum([entry.download for entry in self.entries if entry.device_type == 'GATEWAY'])

    def get_total_upload(self):
        return sum([entry.upload for entry in self.entries if entry.device_type == 'GATEWAY'])

    