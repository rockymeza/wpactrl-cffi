"""
wpactrl defines a single class, WPACtrl, that must be instantiated with the
pathname of a UNIX domain socket control interface of a wpa_supplicant/hostapd
daemon.

Once a WPACtrl object has been instantiated, it may call several helper methods
to interact with the wpa_supplicant/hostapd daemon.  If an error occurs, a
wpactrl.error exception is raised.

The destructor of a WPACtrl instance closes the connection to the control
interface socket.

Recommendations for the use of wpa_supplicant/hostapd control interface access
in external programs are at:
    <http://w1.fi/wpa_supplicant/devel/ctrl_iface_page.html>
"""
from ._ffi import lib, ffi


def version():
    return (1, 0, 1)


class error(Exception):
    pass


class WPACtrl(object):
    def __init__(self, path):
        self.attached = 0
        self.ctrl_iface_path = path.encode('utf-8')
        self.ctrl_iface = lib.wpa_ctrl_open(self.ctrl_iface_path)
        if self.ctrl_iface == ffi.NULL:
            raise error('wpa_ctrl_open failed')

    def request(self, cmd):
        """
        Send a command to wpa_supplicant/hostapd. Returns the command response
        in a string.
        """
        if not isinstance(cmd, bytes):
            cmd = cmd.encode('utf-8')

        buf = ffi.new('char[2048]')
        buflen = ffi.new('size_t *', ffi.sizeof(buf))

        ret = lib.wpa_ctrl_request(self.ctrl_iface, cmd, len(cmd), buf, buflen, ffi.NULL)

        if ret == 0:
            return ffi.string(buf).decode('utf-8')
        elif ret == -1:
            raise error('wpa_ctrl_request failed')
        elif ret == -2:
            raise error('wpa_ctrl_request timed out')
        else:
            raise error('wpa_ctrl_request returned unknown error')

    def attach(self):
        """
        Register as an event monitor for the control interface.
        """
        if self.attached:
            return None

        ret = lib.wpa_ctrl_attach(self.ctrl_iface)

        if ret == 0:
            self.attached = 1
        elif ret == -1:
            raise error('wpa_ctrl_attach failed')
        elif ret == -2:
            raise error('wpa_ctrl_attach timed out')
        else:
            raise error('wpa_ctrl_attach returned unknown error')

    def detach(self):
        """
        Unregister event monitor from the control interface.
        """
        if not self.attached:
            return None

        ret = lib.wpa_ctrl_detach(self.ctrl_iface)

        if ret == 0:
            self.attached = 0
        elif ret == -1:
            raise error('wpa_ctrl_detach failed')
        elif ret == -2:
            raise error('wpa_ctrl_detach timed out')
        else:
            raise error('wpa_ctrl_detach returned unknown error')

    def pending(self):
        """
        Check if any events/messages are pending. Returns True if messages are pending,
        otherwise False.
        """
        ret = lib.wpa_ctrl_pending(self.ctrl_iface)

        if ret == 1:
            return True
        elif ret == 0:
            return False
        elif ret == -1:
            raise error('wpa_ctrl_pending failed')
        else:
            raise error('wpa_ctrl_pending returned unknown error')

    def recv(self):
        """
        Recieve a pending event/message from ctrl socket. Returns a message string.
        """
        buf = ffi.new('char[256]')
        buflen = ffi.new('size_t *', ffi.sizeof(buf))

        ret = lib.wpa_ctrl_recv(self.ctrl_iface, buf, buflen)

        if ret == 0:
            return ffi.string(buf).decode('utf-8')
        elif ret == -1:
            raise error('wpa_ctrl_recv failed')
        else:
            raise error('wpa_ctrl_recv returned unknown error')

    def scanresults(self):
        """
        Return list of scan results. Each element of the scan result list is a string
        of properties for a single BSS. This method is specific to wpa_supplicant.
        """
        results = []

        for i in range(1000):
            buf = self.request('BSS {cell}'.format(cell=i))

            if 'bssid=' in buf:
                results.append(buf)

        return results

    def close(self):
        if self.ctrl_iface:
            if self.attached:
                self.detach()
            lib.wpa_ctrl_close(self.ctrl_iface)
        self.ctrl_iface_path = None
