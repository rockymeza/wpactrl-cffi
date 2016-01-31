from cffi import FFI


ffi = FFI()

ffi.cdef("""
struct wpa_ctrl * wpa_ctrl_open(const char *ctrl_path);
void wpa_ctrl_close(struct wpa_ctrl *ctrl);
int wpa_ctrl_request(struct wpa_ctrl *ctrl, const char *cmd, size_t cmd_len,
                     char *reply, size_t *reply_len,
                     void (*msg_cb)(char *msg, size_t len));
int wpa_ctrl_attach(struct wpa_ctrl *ctrl);
int wpa_ctrl_detach(struct wpa_ctrl *ctrl);
int wpa_ctrl_recv(struct wpa_ctrl *ctrl, char *reply, size_t *reply_len);
int wpa_ctrl_pending(struct wpa_ctrl *ctrl);
int wpa_ctrl_get_fd(struct wpa_ctrl *ctrl);
""")


ffi.set_source(
    'wpactrl._ffi',
    """
        #include "wpa_ctrl.h"
    """,
    sources=['include/wpa_ctrl.c'],
    include_dirs=['include'],
)


if __name__ == "__main__":
    ffi.compile()
