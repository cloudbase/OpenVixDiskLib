# Copyright 2016 Cloudbase Solutions Srl
# All Rights Reserved.

"""Python bindings for the VDDK vixdisklib library. Superseded by the
openvixdisklib, which avoids the proprietary VDDK SDK.

This module is used by the integration tests in order to cross-check the
openvixdisklib library. ctypes layouts follow `.vddk/vixDiskLib.h`.
"""

import contextlib
import ctypes
import logging
import os
import traceback

from tests.integration import vix_disklib_errors

LOG = logging.getLogger(__name__)

VIXDISKLIB_VERSION_MAJOR = 8
VIXDISKLIB_VERSION_MINOR = 0

VIXDISKLIB_SECTOR_SIZE = 512

VIXDISKLIB_CRED_UID = 1

VIXDISKLIB_FLAG_OPEN_UNBUFFERED = 1
VIXDISKLIB_FLAG_OPEN_SINGLE_LINK = 2
VIXDISKLIB_FLAG_OPEN_READ_ONLY = 4

# NBD compression flags
VIXDISKLIB_FLAG_OPEN_COMPRESSION_ZLIB = 16
VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ = 32
VIXDISKLIB_FLAG_OPEN_COMPRESSION_SKIPZ = 64

VIX_SUPPORTED_COMPATIBILITY_MODES = [
    "6.0", "6.5", "6.7", "7.0", "8.0"]


class VixDiskLibUidPasswdCreds(ctypes.Structure):
    _fields_ = [
        ("userName", ctypes.c_char_p),
        ("password", ctypes.c_char_p),
    ]


class VixDiskLibSessionIdCreds(ctypes.Structure):
    _fields_ = [
        ("cookie", ctypes.c_char_p),
        ("userName", ctypes.c_char_p),
        ("key", ctypes.c_char_p),
    ]


class VixDiskLibCreds(ctypes.Union):
    _fields_ = [
        ("uid", VixDiskLibUidPasswdCreds),
        ("sessionId", VixDiskLibSessionIdCreds),
    ]


class VixDiskLibConnectParams(ctypes.Structure):
    _fields_ = [
        ("vmxSpec", ctypes.c_char_p),
        ("serverName", ctypes.c_char_p),
        ("thumbPrint", ctypes.c_char_p),
        # Note: this is 32bit on Windows
        ("privateUse", ctypes.c_longlong),
        ("credType", ctypes.c_uint32),
        ("creds", VixDiskLibCreds),
        ("port", ctypes.c_uint32),
        ("nfcHostPort", ctypes.c_uint32),
        ("vimApiVer", ctypes.c_char_p),
    ]


class VixDiskLibConnection(ctypes.Structure):
    _fields_ = []


def get_buffer(size):
    return ctypes.create_string_buffer(size)


class VixDiskLibHandle(object):
    """ Class which acts as a proxy for vixDiskLib-related operations:
    """
    def __init__(
            self, config_path=None, vixdisklib_compatibility_version=None):
        self._vix_disklib = ctypes.cdll.LoadLibrary(
            self.get_vix_disklib_name())
        self._setup_vix_disklib()

        if config_path:
            config_path = config_path.encode()

        target_versions = VIX_SUPPORTED_COMPATIBILITY_MODES
        if vixdisklib_compatibility_version:
            target_versions = [vixdisklib_compatibility_version]
        LOG.debug("vixDiskLib versions targeted: %s", target_versions)

        # NOTE: iterate through all versions and try to initialize using each:
        version_used = None
        for version in reversed(target_versions):
            major_ver = None
            minor_ver = None
            try:
                major_ver, minor_ver = version.split(".")
                major_ver = int(major_ver)
                minor_ver = int(minor_ver)
            except ValueError as ex:
                raise ValueError(
                    "Unsupported vixDiskLib version format '%s'. vixDiskLib "
                    "compatibility mode must be of the form "
                    "'$major.$minor'" % version) from ex

            try:
                self._check_err(self._vix_disklib.VixDiskLib_InitEx(
                    major_ver, minor_ver, None, None, None, None, config_path))
                version_used = version
                break
            except Exception:
                LOG.debug(
                    "Failed to initialize vixDiskLib using compatibility "
                    "version '%s'. Trying next version. Error trace: %s",
                    version, traceback.format_exc())

        if not version_used:
            raise Exception(
                "Could not initialize vixDiskLib with any of the following "
                "versions: %s" % target_versions)

        LOG.info(
            "Successfully initialized vixDiskLib with target version '%s'",
            version_used)

    @classmethod
    def get_vix_disklib_name(cls):
        vixDiskLibName = None
        if os.name == 'nt':
            vixDiskLibName = 'vixDiskLib.dll'
        else:
            vixDiskLibName = 'libvixDiskLib.so'
        return vixDiskLibName

    def _setup_vix_disklib(self):
        self._vix_disklib.VixDiskLib_InitEx.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        self._vix_disklib.VixDiskLib_InitEx.restype = ctypes.c_uint64

        self._vix_disklib.VixDiskLib_GetErrorText.argtypes = [
            ctypes.c_uint64, ctypes.c_char_p]
        self._vix_disklib.VixDiskLib_GetErrorText.restype = ctypes.c_void_p

        self._vix_disklib.VixDiskLib_FreeErrorText.arg_types = [
            ctypes.c_char_p]
        self._vix_disklib.VixDiskLib_FreeErrorText.restype = None

        self._vix_disklib.VixDiskLib_ListTransportModes.argtypes = []
        self._vix_disklib.VixDiskLib_ListTransportModes.restype = (
            ctypes.c_char_p)

        self._vix_disklib.VixDiskLib_GetTransportMode.argtypes = [
            ctypes.c_void_p]
        self._vix_disklib.VixDiskLib_GetTransportMode.restype = (
            ctypes.c_char_p)

        self._vix_disklib.VixDiskLib_ConnectEx.argtypes = [
            ctypes.POINTER(VixDiskLibConnectParams), ctypes.c_char,
            ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        self._vix_disklib.VixDiskLib_ConnectEx.restype = ctypes.c_uint64

        self._vix_disklib.VixDiskLib_Open.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p)]
        self._vix_disklib.VixDiskLib_Open.restype = ctypes.c_uint64

        self._vix_disklib.VixDiskLib_Read.argtypes = [
            ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p]
        self._vix_disklib.VixDiskLib_Read.restype = ctypes.c_uint64

        self._vix_disklib.VixDiskLib_Write.argtypes = [
            ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p]
        self._vix_disklib.VixDiskLib_Write.restype = ctypes.c_uint64

        self._vix_disklib.VixDiskLib_GetMetadataKeys.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint64)]
        self._vix_disklib.VixDiskLib_GetMetadataKeys.restype = ctypes.c_uint64

        self._vix_disklib.VixDiskLib_ReadMetadata.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint64)]
        self._vix_disklib.VixDiskLib_ReadMetadata.restype = ctypes.c_uint64

        self._vix_disklib.VixDiskLib_Close.argtypes = [ctypes.c_void_p]
        self._vix_disklib.VixDiskLib_Close.restype = ctypes.c_uint64

        self._vix_disklib.VixDiskLib_Disconnect.argtypes = [ctypes.c_void_p]
        self._vix_disklib.VixDiskLib_Disconnect.restype = ctypes.c_uint64

        self._vix_disklib.VixDiskLib_Exit.argtypes = []
        self._vix_disklib.VixDiskLib_Exit.restype = None

    def _check_err(self, err, allowed_values=[vix_disklib_errors.VIX_OK]):
        if err not in allowed_values:
            err_msg = self._vix_disklib.VixDiskLib_GetErrorText(err, None)
            err_msg_copy = str(ctypes.cast(
                err_msg, ctypes.c_char_p).value.decode())
            self._vix_disklib.VixDiskLib_FreeErrorText(
                ctypes.cast(err_msg, ctypes.c_char_p))

            msg = None
            if err == vix_disklib_errors.VIX_E_OUT_OF_MEMORY:
                msg = (
                    "The ESXi host performing the CBT export ran out of RAM. "
                    "The host performing the export is automatically chosen "
                    "by vCenter, so enough RAM to run the export is required "
                    "on all hosts. To force the export from the specific host "
                    "the VM is on, create a Coriolis endpoint with the DNS "
                    "name/IP address of that host.")
            if err == vix_disklib_errors.VIX_E_HOST_NETWORK_CONN_REFUSED:
                msg = (
                    "The ESXi host performing the CBT export refused "
                    "connection. The host is chosen automatically by vCenter, "
                    "so please ensure that the Coriolis deployment "
                    "can dial TCP/902 on all of the ESXi hosts of a vSphere, "
                    "and that DNS name resolution and firewalls are setup to "
                    "facilitate this. Alternatively, try connecting Coriolis "
                    "directly to the specific ESXi host which is running the "
                    "VM(s) to be migrated by creating a Coriolis endpoint "
                    "using the DNS name/IP address of the host itself.")

            if err == vix_disklib_errors.VIX_E_CANNOT_CONNECT_TO_HOST:
                msg = (
                    "Coriolis lost connection to the ESXi host performing the "
                    "CBT export. If the Coriolis Endpoint connects to a "
                    "vSphere host, please try connecting Coriolis to the ESXi "
                    "host directly. If problem persists, try re-enabling CBT "
                    "on the VM, or moving it to another ESXi host.")

            err_msg = err_msg_copy
            if msg:
                LOG.debug("Original vixDiskLib error message: %s", err_msg_copy)
                err_msg = msg

            raise Exception(err_msg)

    def get_transport_modes(self):
        transport_modes = self._vix_disklib.VixDiskLib_ListTransportModes()
        return transport_modes.decode().split(':')

    def get_transport_mode(self, disk_handle):
        t_mode = self._vix_disklib.VixDiskLib_GetTransportMode(disk_handle)
        return t_mode.decode()

    @contextlib.contextmanager
    def connect(
            self, server_name, thumbprint, username, password,
            vmx_spec=None, snapshot_ref=None, read_only=True,
            transport_modes=None, port=443):
        LOG.debug("Connecting VixDiskLib: %s", server_name)

        connectParams = VixDiskLibConnectParams()

        connectParams.serverName = server_name.encode()
        if vmx_spec:
            connectParams.vmxSpec = vmx_spec.encode()
        if thumbprint:
            connectParams.thumbPrint = thumbprint.encode()

        connectParams.credType = VIXDISKLIB_CRED_UID
        connectParams.creds.uid.userName = username.encode()
        connectParams.creds.uid.password = password.encode()
        connectParams.port = port

        if transport_modes:
            transport_modes = transport_modes.encode()

        if snapshot_ref:
            snapshot_ref = snapshot_ref.encode()

        conn = ctypes.c_void_p()
        self._check_err(self._vix_disklib.VixDiskLib_ConnectEx(
            connectParams, read_only, snapshot_ref, transport_modes,
            ctypes.byref(conn)))
        try:
            yield conn
        finally:
            self.disconnect(conn)

    @contextlib.contextmanager
    def open(self, conn, disk_path, flags=VIXDISKLIB_FLAG_OPEN_READ_ONLY):
        LOG.debug("Openning VixDiskLib disk: %s", disk_path)

        disk_handle = ctypes.c_void_p()
        self._check_err(self._vix_disklib.VixDiskLib_Open(
            conn, disk_path.encode(), flags, ctypes.byref(disk_handle)))
        try:
            yield disk_handle
        finally:
            self.close(disk_handle)

    def read(self, disk_handle, start_sector, num_sectors, buf):
        self._check_err(self._vix_disklib.VixDiskLib_Read(
            disk_handle, start_sector, num_sectors, buf))

    def write(self, disk_handle, start_sector, num_sectors, buf):
        """Write ``num_sectors`` from ``buf`` starting at ``start_sector``."""
        self._check_err(self._vix_disklib.VixDiskLib_Write(
            disk_handle, start_sector, num_sectors, buf))

    def close(self, disk_handle):
        LOG.debug("Closing VixDiskLib disk handle: %s", disk_handle)
        self._check_err(self._vix_disklib.VixDiskLib_Close(disk_handle))

    def disconnect(self, conn):
        LOG.debug("Disconnecting VixDiskLib")
        self._check_err(self._vix_disklib.VixDiskLib_Disconnect(conn))

    def exit(self):
        self._vix_disklib.VixDiskLib_Exit()
