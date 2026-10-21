/* SPDX-License-Identifier: MIT
 * Real seat input sequences adapted from Weston's tests/weston-test.c:
 * Copyright © 2012 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * FINANCIAL CI ONLY, distinct protocol and fixed 1800s ceiling. Not a product module and not a human-approval mechanism.
 *
 * Private, inherited AF_UNIX/SOCK_SEQPACKET endpoint. No control wl_global,
 * pathname socket, process launch, file access, clipboard, or received FDs.
 * Build ONLY in the reviewed disposable CI against official Weston 14.0.2-1.
 * Uses that release's public desktop.h and its exact source-private renderer
 * and backend headers; do not substitute a different ABI.
 *
 * Source references (all under Weston 14.0.2 source):
 * include/libweston/desktop.h: get_desktop_surface/get_app_id/get_parent.
 * tests/weston-test.c: test_seat_init, activate_surface, move_pointer,
 * send_button, send_key. Those real seat APIs are used, not its test global.
 * libweston/compositor.c: weston_surface_commit_state emits commit_signal
 * after applying the client buffer and invoking the ordinary shell.
 * libweston/pixman-renderer.c: repaint_output emits output->frame_signal
 * AFTER repaint_surfaces/copy_to_hw_buffer; read_pixels copies that buffer.
 * libweston/backend-headless/headless.c: repaint calls the renderer before
 * scheduling finish_frame. This witnesses rendered headless output, not a
 * physical monitor, human visibility, or human approval.
 *
 * Commands: eight little-endian u32s, magic/version/sequence/op/a/b/c/d.
 * Replies: twelve little-endian u32s, magic/version/sequence/kind/status/
 * commit/frame/width/height/offset/length/last_input_sequence, then optional
 * exactly length bytes for CHUNK. No public logs contain protocol contents.
 */
#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/input-event-codes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <libweston/libweston.h>
#include <libweston/desktop.h>
#include "backend.h"
#include "libweston-internal.h"
#include "pixel-formats.h"

#define MAGIC 0x31464943u
#define VERSION 1u
#define WIDTH 1280u
#define HEIGHT 800u
#define FRAME_BYTES (WIDTH * HEIGHT * 4u)
#define CHUNK_BYTES 32768u
#define MAX_COMMANDS 524288u
#define MAX_FRAMES 256u
#define MAX_PROGRESS 8192u
#define MAX_SURFACES 32u
#define MAX_COMMITS 262144u
#define SESSION_NS (1800ull * 1000000000ull)
#define APP_ID "org.wholepact.CoordinatorFinancialQualification"

enum operation { BIND = 1, FOCUS, MOVE, BUTTON, KEY, FRAME, STOP, SCROLL_DOWN, CLOSE_WINDOW, PROGRESS, SCROLL_UP };
enum reply_kind { ACK = 1, IMAGE, CHUNK, ERROR, READY, FRAME_BARRIER };
enum failure { OK = 0, PROTOCOL = 1, DEADLINE, LIMIT, TARGET, INPUT,
               OUTPUT, READBACK, DISCONNECTED, INTERNAL };

/* Closed diagnostic tags only; every original TARGET condition is unchanged. */
enum target_reason { TARGET_NONE = 0, TARGET_PARENT_OR_RESOURCE,
    TARGET_CREDENTIALS, TARGET_DUPLICATE_APP_ID, TARGET_OTHER_DESKTOP,
    TARGET_RETAINED_IDENTITY, TARGET_UNMAPPED, TARGET_DESTROYED,
    TARGET_BIND_ARGUMENTS, TARGET_COMMAND_PRECONDITION, TARGET_CLOSE_DESKTOP };
struct control;
struct watched_surface {
    struct wl_list link;
    struct control *control;
    struct weston_surface *surface;
    struct wl_listener commit, destroy, unmap;
    uint32_t commits, commit_events;
};

struct control {
    struct weston_compositor *compositor;
    struct weston_seat seat;
    bool seat_ready, dead, bound, bind_requested, focused, focus_controlled, button_down;
    bool key_down[KEY_MAX + 1];
    unsigned held_keys, surface_count;
    enum target_reason target_reason;
    int fd;
    uint64_t original_deadline, session_deadline;
    uint32_t sequence, pending, pending_op, input_sequence;
    uint32_t frames, captures, progress, minimum_commit, minimum_frame;
    uint32_t image_commit, image_frame, image_input, image_offset;
    bool image_header_pending, image_sending;
    pid_t expected_pid;
    struct wl_client *client;
    struct watched_surface *target;
    struct weston_desktop_surface *desktop;
    struct weston_output *output;
    unsigned char *pixels;
    struct wl_event_source *socket_source, *timer;
    struct wl_list surfaces;
    struct wl_listener create_surface, output_created, output_destroyed;
    struct wl_listener output_frame, destroy;
};

static uint64_t
now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) < 0)
        return UINT64_MAX;
    return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

static bool
identity_valid(void)
{
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    return getresuid(&ruid, &euid, &suid) == 0 &&
        getresgid(&rgid, &egid, &sgid) == 0 &&
        ruid == 10001 && euid == 10001 && suid == 10001 &&
        rgid == 10001 && egid == 10001 && sgid == 10001 &&
        getgroups(0, NULL) == 0 && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1;
}

static void
header(struct control *c, uint32_t *h, uint32_t kind, uint32_t status,
       uint32_t commit, uint32_t frame, uint32_t offset, uint32_t length,
       uint32_t input)
{
    uint32_t values[12] = { MAGIC, VERSION, c->pending, kind, status,
        commit, frame, kind == IMAGE || kind == CHUNK ? WIDTH : 0,
        kind == IMAGE || kind == CHUNK ? HEIGHT : 0, offset, length, input };
    for (unsigned i = 0; i < 12; ++i)
        h[i] = htole32(values[i]);
}

static void
fail(struct control *c, enum failure status)
{
    uint32_t h[12];
    if (c->dead)
        return;
    c->dead = true;
    header(c, h, ERROR, status, 0, 0, 0, 0, 0);
    if (status == TARGET) h[5] = htole32(c->target_reason);
    /* One best-effort finite error, no retries or textual diagnostics. */
    (void)send(c->fd, h, sizeof h, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (c->socket_source) {
        wl_event_source_remove(c->socket_source);
        c->socket_source = NULL;
    }
    if (c->timer) {
        wl_event_source_remove(c->timer);
        c->timer = NULL;
    }
    close(c->fd);
    c->fd = -1;
    if (c->pixels)
        explicit_bzero(c->pixels, FRAME_BYTES);
    weston_compositor_exit_with_code(c->compositor, 1);
}

static void
fail_target(struct control *c, enum target_reason reason)
{
    c->target_reason = reason;
    fail(c, TARGET);
}

static bool
live(struct control *c)
{
    uint64_t now = now_ns();
    if (!c->dead && (now >= c->original_deadline || now >= c->session_deadline))
        fail(c, DEADLINE);
    return !c->dead;
}

static bool
output_valid(struct control *c)
{
    struct weston_output *o = c->output;
    return o && c->compositor->renderer &&
        c->compositor->renderer->type == WESTON_RENDERER_PIXMAN &&
        c->compositor->renderer->read_pixels &&
        weston_get_backend_type(o->backend) == WESTON_BACKEND_HEADLESS &&
        o->width == (int)WIDTH && o->height == (int)HEIGHT &&
        o->current_mode && o->current_mode->width == (int)WIDTH &&
        o->current_mode->height == (int)HEIGHT && o->current_scale == 1 &&
        o->transform == WL_OUTPUT_TRANSFORM_NORMAL &&
        o->pos.c.x == 0 && o->pos.c.y == 0 && !o->destroying &&
        !o->repaint_only_on_capture;
}

static bool
ack(struct control *c)
{
    uint32_t h[12];
    header(c, h, ACK, OK, c->target ? c->target->commits : 0,
           c->frames, 0, 0, c->input_sequence);
    if (send(c->fd, h, sizeof h, MSG_DONTWAIT | MSG_NOSIGNAL) != sizeof h) {
        fail(c, DISCONNECTED);
        return false;
    }
    c->pending = c->pending_op = 0;
    return true;
}

/* Recheck all created surfaces at commits, every command, each frame, and
 * every timer tick. A role/app-id/client change is never used for rebinding.
 * Do not retain desktop metadata listeners: desktop objects may disappear
 * before their wl_surface and expose no public destruction listener. */
static bool
validate_target(struct control *c)
{
    struct watched_surface *w, *match = NULL;
    unsigned matches = 0;
    if (!live(c))
        return false;
    wl_list_for_each(w, &c->surfaces, link) {
        struct weston_desktop_surface *d =
            weston_surface_get_desktop_surface(w->surface);
        const char *app = d ? weston_desktop_surface_get_app_id(d) : NULL;
        if (app && strcmp(app, APP_ID) == 0) {
            pid_t pid;
            uid_t uid;
            gid_t gid;
            struct wl_client *client;
            if (!w->surface->resource || weston_desktop_surface_get_parent(d)) {
                fail_target(c, TARGET_PARENT_OR_RESOURCE);
                return false;
            }
            client = wl_resource_get_client(w->surface->resource);
            wl_client_get_credentials(client, &pid, &uid, &gid);
            if (c->bind_requested &&
                (pid != c->expected_pid || uid != getuid() || gid != getgid())) {
                fail_target(c, TARGET_CREDENTIALS);
                return false;
            }
            match = w;
            if (++matches > 1) {
                fail_target(c, TARGET_DUPLICATE_APP_ID);
                return false;
            }
        } else if (c->bound && d && weston_surface_is_mapped(w->surface)) {
            /* No other native application window may take input/occlude it. */
            fail_target(c, TARGET_OTHER_DESKTOP);
            return false;
        }
    }
    if (c->bound) {
        if (matches != 1 || match != c->target ||
            weston_surface_get_desktop_surface(match->surface) != c->desktop ||
            wl_resource_get_client(match->surface->resource) != c->client ||
            !weston_surface_is_mapped(match->surface)) {
            fail_target(c, TARGET_RETAINED_IDENTITY);
            return false;
        }
        if (c->focus_controlled && weston_seat_get_keyboard(&c->seat)->focus !=
            (c->focused ? c->target->surface : NULL)) {
            fail(c, INPUT);
            return false;
        }
    } else if (c->bind_requested && matches == 1 && output_valid(c) &&
               weston_surface_is_mapped(match->surface) && match->commits > 0) {
        c->bound = true;
        c->target = match;
        c->desktop = weston_surface_get_desktop_surface(match->surface);
        c->client = wl_resource_get_client(match->surface->resource);
        return ack(c);
    }
    return true;
}

static void
surface_committed(struct wl_listener *listener, void *data)
{
    struct watched_surface *w = wl_container_of(listener, w, commit);
    (void)data;
    if (++w->commit_events > MAX_COMMITS) {
        fail(w->control, LIMIT);
        return;
    }
    /* Exact 14.0.2 compositor.c emits commit_signal before resetting
     * pending.status. Count actual top-level buffer commits, not empty
     * callback-only commits. The target cannot be a synchronized subsurface. */
    if ((w->surface->pending.status & WESTON_SURFACE_DIRTY_BUFFER) &&
        weston_surface_has_content(w->surface))
        ++w->commits;
    (void)validate_target(w->control);
}

static void
surface_unmapped(struct wl_listener *listener, void *data)
{
    struct watched_surface *w = wl_container_of(listener, w, unmap);
    (void)data;
    if (w->control->target == w)
        fail_target(w->control, TARGET_UNMAPPED);
}

static void
surface_destroyed(struct wl_listener *listener, void *data)
{
    struct watched_surface *w = wl_container_of(listener, w, destroy);
    (void)data;
    if (w->control->target == w) {
        w->control->target = NULL;
        fail_target(w->control, TARGET_DESTROYED);
    }
    wl_list_remove(&w->commit.link);
    wl_list_remove(&w->destroy.link);
    wl_list_remove(&w->unmap.link);
    wl_list_remove(&w->link);
    free(w);
}

static void
surface_created(struct wl_listener *listener, void *data)
{
    struct control *c = wl_container_of(listener, c, create_surface);
    struct watched_surface *w;
    if (!live(c))
        return;
    /* Lifetime count, not concurrent count: destruction cannot reset budget. */
    if (++c->surface_count > MAX_SURFACES || !(w = calloc(1, sizeof *w))) {
        fail(c, LIMIT);
        return;
    }
    w->control = c;
    w->surface = data;
    w->commit.notify = surface_committed;
    w->destroy.notify = surface_destroyed;
    w->unmap.notify = surface_unmapped;
    wl_signal_add(&w->surface->commit_signal, &w->commit);
    wl_signal_add(&w->surface->destroy_signal, &w->destroy);
    wl_signal_add(&w->surface->unmap_signal, &w->unmap);
    wl_list_insert(&c->surfaces, &w->link);
}

static bool
flush_image(struct control *c)
{
    unsigned char packet[48 + CHUNK_BYTES];
    uint32_t h[12];
    while (c->image_sending && live(c)) {
        uint32_t length = c->image_header_pending ? 0 :
            (FRAME_BYTES - c->image_offset < CHUNK_BYTES ?
             FRAME_BYTES - c->image_offset : CHUNK_BYTES);
        header(c, h, c->image_header_pending ? IMAGE : CHUNK, OK,
               c->image_commit, c->image_frame, c->image_offset,
               c->image_header_pending ? FRAME_BYTES : length, c->image_input);
        memcpy(packet, h, sizeof h);
        if (length)
            memcpy(packet + sizeof h, c->pixels + c->image_offset, length);
        ssize_t n = send(c->fd, packet, sizeof h + length,
                         MSG_DONTWAIT | MSG_NOSIGNAL);
        explicit_bzero(packet, sizeof packet);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            wl_event_source_fd_update(c->socket_source,
                                      WL_EVENT_READABLE | WL_EVENT_WRITABLE);
            return true;
        }
        if (n != (ssize_t)(sizeof h + length)) {
            fail(c, DISCONNECTED);
            return false;
        }
        c->image_header_pending = false;
        c->image_offset += length;
        if (c->image_offset == FRAME_BYTES) {
            c->image_sending = false;
            explicit_bzero(c->pixels, FRAME_BYTES);
            c->pending = c->pending_op = 0;
            wl_event_source_fd_update(c->socket_source, WL_EVENT_READABLE);
        }
    }
    return !c->dead;
}

/* Exact current surface-to-output correspondence, not shell intention. The
 * API and coordinate-space constructor are Weston 14.0.2 libweston.h. */
static bool
view_covers_output(struct weston_paint_node *node)
{
    const int xs[4] = { 0, WIDTH, 0, WIDTH };
    const int ys[4] = { 0, 0, HEIGHT, HEIGHT };
    pixman_box32_t box = { 0, 0, WIDTH, HEIGHT };
    if (node->view->transform.dirty ||
        pixman_region32_contains_rectangle(&node->visible, &box) != PIXMAN_REGION_IN)
        return false;
    for (unsigned i = 0; i < 4; ++i) {
        struct weston_coord_surface local =
            weston_coord_surface(xs[i], ys[i], node->surface);
        struct weston_coord_global global =
            weston_coord_surface_to_global(node->view, local);
        if (global.c.x != xs[i] || global.c.y != ys[i])
            return false;
    }
    return true;
}

static void
frame_rendered(struct wl_listener *listener, void *data)
{
    struct control *c = wl_container_of(listener, c, output_frame);
    struct weston_paint_node *node;
    bool painted = false;
    if (!validate_target(c))
        return;
    if (++c->frames > MAX_COMMITS || !output_valid(c)) {
        fail(c, OUTPUT);
        return;
    }
    if ((c->pending_op != FRAME && c->pending_op != PROGRESS) || c->image_sending ||
        c->target->commits <= c->minimum_commit || c->frames <= c->minimum_frame)
        return;
    wl_list_for_each(node, &c->output->paint_node_z_order_list, z_order_link) {
        if (node->surface == c->target->surface && node->valid_transform &&
            node->surf_xform_valid && weston_surface_has_content(node->surface) &&
            node->plane == &c->output->primary_plane &&
            node->view->output == c->output &&
            node->view->alpha == 1.0f && view_covers_output(node)) {
            pixman_region32_t repainted;
            pixman_region32_init(&repainted);
            pixman_region32_intersect(&repainted, &node->visible, data);
            painted = pixman_region32_not_empty(&repainted);
            pixman_region32_fini(&repainted);
            if (painted)
                break;
        }
    }
    if (!painted || c->target->surface->output != c->output ||
        c->target->surface->width != (int)WIDTH ||
        c->target->surface->height != (int)HEIGHT) {
        fail(c, OUTPUT);
        return;
    }
    /* Same actual target commit, output paint, mapping and identity guards as
     * FRAME. This is backpressure only: no pixels or UI approval evidence. */
    if (c->pending_op == PROGRESS) {
        (void)ack(c);
        return;
    }
    const struct pixel_format_info *format =
        pixel_format_get_info_by_pixman(PIXMAN_a8r8g8b8);
    if (!format || c->compositor->renderer->read_pixels(c->output, format,
                       c->pixels, 0, 0, WIDTH, HEIGHT) < 0) {
        fail(c, READBACK);
        return;
    }
    c->image_commit = c->target->commits;
    c->image_frame = c->frames;
    c->image_input = c->input_sequence;
    c->image_offset = 0;
    c->image_header_pending = c->image_sending = true;
    (void)flush_image(c);
}

static void
output_created(struct wl_listener *listener, void *data)
{
    struct control *c = wl_container_of(listener, c, output_created);
    if (c->output) {
        fail(c, OUTPUT);
        return;
    }
    c->output = data;
    c->output_frame.notify = frame_rendered;
    wl_signal_add(&c->output->frame_signal, &c->output_frame);
}

static void
output_destroyed(struct wl_listener *listener, void *data)
{
    struct control *c = wl_container_of(listener, c, output_destroyed);
    if (data == c->output) {
        wl_list_remove(&c->output_frame.link);
        wl_list_init(&c->output_frame.link);
        c->output = NULL;
        fail(c, OUTPUT);
    }
}

static bool
allowed_key(uint32_t key)
{
    /* US printable ASCII, Tab/Enter/Backspace, Shift, and Ctrl+A only as
     * supplied by the closed Python encoder. No Alt/Super/F-keys/system keys. */
    return (key >= KEY_1 && key <= KEY_P) ||
           (key >= KEY_A && key <= KEY_GRAVE) ||
           (key >= KEY_LEFTSHIFT && key <= KEY_SLASH) ||
           key == KEY_LEFTCTRL || key == KEY_SPACE ||
           key == KEY_LEFTBRACE || key == KEY_RIGHTBRACE || key == KEY_ENTER;
}

static int
init_keyboard(struct weston_seat *seat)
{
    const struct xkb_rule_names names = {
        .rules = "evdev", .model = "pc105", .layout = "us",
        .variant = "", .options = "",
    };
    struct xkb_context *context = xkb_context_new(
        XKB_CONTEXT_NO_DEFAULT_INCLUDES | XKB_CONTEXT_NO_ENVIRONMENT_NAMES);
    struct xkb_keymap *keymap = NULL;
    int result = -1;
    if (!context)
        return -1;
    /* Pinned official xkb-data only, never HOME/XKB_CONFIG_ROOT includes. */
    if (xkb_context_include_path_append(context, "/usr/share/X11/xkb") == 1)
        keymap = xkb_keymap_new_from_names(context, &names, XKB_KEYMAP_COMPILE_NO_FLAGS);
    if (keymap) {
        result = weston_seat_init_keyboard(seat, keymap);
        xkb_keymap_unref(keymap);
    }
    xkb_context_unref(context);
    return result;
}

static void
dispatch(struct control *c, const uint32_t *v)
{
    uint32_t op = v[3], a = v[4], b = v[5];
    struct timespec t;
    struct weston_keyboard *keyboard = weston_seat_get_keyboard(&c->seat);
    struct weston_pointer *pointer = weston_seat_get_pointer(&c->seat);
    if (!validate_target(c))
        return;
    if (c->pending || v[0] != MAGIC || v[1] != VERSION ||
        v[2] != c->sequence + 1 || v[2] > MAX_COMMANDS || v[6] || v[7]) {
        fail(c, PROTOCOL);
        return;
    }
    c->sequence = c->pending = v[2];
    c->pending_op = op;
    if (op == BIND) {
        if (c->bind_requested || a <= 1 || a > INT_MAX || b) {
            fail_target(c, TARGET_BIND_ARGUMENTS);
            return;
        }
        c->expected_pid = (pid_t)a;
        c->bind_requested = true;
        (void)validate_target(c); /* Deferred until the actual client maps. */
        return;
    }
    if (op == STOP && !a && !b && !c->button_down && !c->held_keys) {
        if (ack(c)) {
            c->dead = true;
            weston_compositor_exit_with_code(c->compositor, 0);
        }
        return;
    }
    if (!c->bound || !output_valid(c) || !keyboard || !pointer ||
        clock_gettime(CLOCK_MONOTONIC, &t) < 0) {
        fail_target(c, TARGET_COMMAND_PRECONDITION);
        return;
    }
    if (op == FRAME || op == PROGRESS) {
        if (a > c->target->commits || b > c->frames ||
            (op == FRAME && ++c->captures > MAX_FRAMES) ||
            (op == PROGRESS && ++c->progress > MAX_PROGRESS) ||
            c->held_keys || c->button_down) {
            fail(c, LIMIT);
            return;
        }
        if (op == PROGRESS && (!c->focused ||
                keyboard->focus != c->target->surface)) {
            fail(c, INPUT);
            return;
        }
        /* Clamp at this actual request receipt, after the caller consumed its
         * source snapshot. An older buffer plus damage_all is not sufficient. */
        c->minimum_commit = a > c->target->commits ? a : c->target->commits;
        c->minimum_frame = b > c->frames ? b : c->frames;
        uint32_t h[12];
        header(c, h, FRAME_BARRIER, OK, c->minimum_commit, c->minimum_frame,
               0, 0, c->input_sequence);
        if (send(c->fd, h, sizeof h, MSG_DONTWAIT | MSG_NOSIGNAL) != sizeof h) {
            fail(c, DISCONNECTED);
            return;
        }
        /* This one distinct observation does not clear the pending FRAME/PROGRESS. */
        weston_compositor_damage_all(c->compositor);
        return;
    }
    if (op == FOCUS && a <= 1 && !b && !c->held_keys && !c->button_down) {
        if (a) {
            weston_seat_set_keyboard_focus(&c->seat, c->target->surface);
            notify_keyboard_focus_in(&c->seat, &keyboard->keys,
                                     STATE_UPDATE_AUTOMATIC);
        } else {
            notify_keyboard_focus_out(&c->seat);
            weston_seat_set_keyboard_focus(&c->seat, NULL);
        }
        c->focused = a != 0;
        c->focus_controlled = true;
        if (keyboard->focus != (a ? c->target->surface : NULL)) {
            fail(c, INPUT);
            return;
        }
    } else if (op == MOVE && a < WIDTH && b < HEIGHT && !c->button_down &&
               c->focused && keyboard->focus == c->target->surface) {
        struct weston_coord_global position = { .c = weston_coord(a, b) };
        struct weston_view *view = weston_compositor_pick_view(c->compositor, position);
        if (!view || view->surface != c->target->surface) {
            fail(c, INPUT);
            return;
        }
        struct weston_pointer_motion_event event = {
            .mask = WESTON_POINTER_MOTION_REL,
            .rel = weston_coord_global_sub(position, pointer->pos).c,
        };
        notify_motion(&c->seat, &t, &event);
        notify_pointer_frame(&c->seat);
        if (!pointer->focus || pointer->focus->surface != c->target->surface ||
            pointer->pos.c.x != position.c.x || pointer->pos.c.y != position.c.y) {
            fail(c, INPUT);
            return;
        }
    } else if ((op == SCROLL_DOWN || op == SCROLL_UP) && !a && !b && c->focused &&
               !c->held_keys && !c->button_down &&
               keyboard->focus == c->target->surface && pointer->focus &&
               pointer->focus->surface == c->target->surface) {
        struct weston_pointer_axis_event event = {
            .axis = WL_POINTER_AXIS_VERTICAL_SCROLL,
            .value = op == SCROLL_UP ? -120.0 : 120.0, .has_discrete = false, .discrete = 0,
        };
        notify_axis(&c->seat, &t, &event);
        notify_pointer_frame(&c->seat);
    } else if (op == CLOSE_WINDOW && !a && !b && !c->held_keys && !c->button_down) {
        struct weston_desktop_surface *desktop =
            weston_surface_get_desktop_surface(c->target->surface);
        if (!desktop) {
            fail_target(c, TARGET_CLOSE_DESKTOP);
            return;
        }
        /* Genuine compositor close request, credential-free smoke only. */
        weston_desktop_surface_close(desktop);
    } else if (op == BUTTON && a <= 1 && !b && c->focused && !c->held_keys &&
               keyboard->focus == c->target->surface && pointer->focus &&
               pointer->focus->surface == c->target->surface &&
               c->button_down != (a != 0)) {
        notify_button(&c->seat, &t, BTN_LEFT, a);
        notify_pointer_frame(&c->seat);
        c->button_down = a != 0;
    } else if (op == KEY && allowed_key(a) && b <= 1 && !c->button_down &&
               c->focused && keyboard->focus == c->target->surface &&
               c->key_down[a] != (b != 0)) {
        /* Ctrl may only form Ctrl+A; never shortcuts invoking file/process UI. */
        if ((c->key_down[KEY_LEFTCTRL] && a != KEY_A && a != KEY_LEFTCTRL) ||
            (a == KEY_LEFTCTRL && b && c->held_keys) ||
            (b && c->held_keys >= 2)) {
            fail(c, INPUT);
            return;
        }
        notify_key(&c->seat, &t, a, b, STATE_UPDATE_AUTOMATIC);
        c->key_down[a] = b != 0;
        c->held_keys += b ? 1 : -1;
    } else {
        fail(c, INPUT);
        return;
    }
    c->input_sequence = c->sequence;
    (void)ack(c);
}

static int
socket_ready(int fd, uint32_t mask, void *data)
{
    struct control *c = data;
    uint32_t raw[8], values[8];
    struct iovec iov = { raw, sizeof raw };
    /* No ancillary buffer: kernel discards/closes received SCM_RIGHTS and
     * MSG_CTRUNC is fatal. There is no FD-passing protocol. */
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
    if (!live(c))
        return 0;
    if (mask & (WL_EVENT_HANGUP | WL_EVENT_ERROR)) {
        fail(c, DISCONNECTED);
        return 0;
    }
    if (mask & WL_EVENT_READABLE) {
        ssize_t n = recvmsg(fd, &msg, MSG_DONTWAIT);
        if (n != sizeof raw || msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
            fail(c, PROTOCOL);
            return 0;
        }
        for (unsigned i = 0; i < 8; ++i)
            values[i] = le32toh(raw[i]);
        dispatch(c, values);
    }
    if (!c->dead && mask & WL_EVENT_WRITABLE)
        (void)flush_image(c);
    return 0;
}

static int
tick(void *data)
{
    struct control *c = data;
    if (validate_target(c) && c->timer && wl_event_source_timer_update(c->timer, 10) < 0)
        fail(c, INTERNAL);
    return 0;
}

static void
destroyed(struct wl_listener *listener, void *data)
{
    struct control *c = wl_container_of(listener, c, destroy);
    struct watched_surface *w, *next;
    (void)data;
    c->dead = true;
    if (c->socket_source)
        wl_event_source_remove(c->socket_source);
    if (c->timer)
        wl_event_source_remove(c->timer);
    if (c->fd >= 0)
        close(c->fd);
    wl_list_for_each_safe(w, next, &c->surfaces, link) {
        wl_list_remove(&w->commit.link);
        wl_list_remove(&w->destroy.link);
        wl_list_remove(&w->unmap.link);
        wl_list_remove(&w->link);
        free(w);
    }
    wl_list_remove(&c->create_surface.link);
    wl_list_remove(&c->output_created.link);
    wl_list_remove(&c->output_destroyed.link);
    wl_list_remove(&c->output_frame.link);
    wl_list_remove(&c->destroy.link);
    if (c->seat_ready)
        weston_seat_release(&c->seat);
    if (c->pixels) {
        explicit_bzero(c->pixels, FRAME_BYTES);
        free(c->pixels);
    }
    explicit_bzero(c, sizeof *c);
    free(c);
}

static bool
number(const char *text, uint64_t *value)
{
    char *end;
    if (!text || !*text || *text < '0' || *text > '9')
        return false;
    errno = 0;
    unsigned long long n = strtoull(text, &end, 10);
    if (errno || *end)
        return false;
    *value = n;
    return true;
}

WL_EXPORT int
wet_module_init(struct weston_compositor *compositor, int *argc, char *argv[])
{
    struct control *c;
    struct weston_output *output;
    struct wl_event_loop *loop;
    struct sockaddr_un address;
    struct ucred peer;
    socklen_t length;
    int type, domain;
    uint64_t fd, original, session, now = now_ns();
    (void)argc;
    (void)argv;
    bool valid = number(getenv("CI_FINANCIAL_CONTROL_FD"), &fd) &&
        number(getenv("CI_FINANCIAL_ORIGINAL_DEADLINE_NS"), &original) &&
        number(getenv("CI_FINANCIAL_SESSION_DEADLINE_NS"), &session);
    unsetenv("CI_FINANCIAL_CONTROL_FD");
    unsetenv("CI_FINANCIAL_ORIGINAL_DEADLINE_NS");
    unsetenv("CI_FINANCIAL_SESSION_DEADLINE_NS");
    if (!valid || fd < 3 || fd > INT_MAX || session > original || !identity_valid() ||
        now >= session || session - now > SESSION_NS ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0 ||
        prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0)
        return -1;
    length = sizeof type;
    if (getsockopt((int)fd, SOL_SOCKET, SO_TYPE, &type, &length) < 0 ||
        type != SOCK_SEQPACKET)
        return -1;
    length = sizeof domain;
    if (getsockopt((int)fd, SOL_SOCKET, SO_DOMAIN, &domain, &length) < 0 ||
        domain != AF_UNIX)
        return -1;
    length = sizeof address;
    if (getsockname((int)fd, (struct sockaddr *)&address, &length) < 0 ||
        length != sizeof(sa_family_t)) /* Only unnamed socketpair endpoints. */
        return -1;
    length = sizeof peer;
    if (getsockopt((int)fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) < 0 ||
        peer.uid != getuid() || peer.gid != getgid() || peer.pid != getppid() ||
        fcntl((int)fd, F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl((int)fd, F_SETFL, O_NONBLOCK) < 0)
        return -1;
    c = calloc(1, sizeof *c);
    if (!c)
        return -1;
    c->fd = (int)fd;
    c->compositor = compositor;
    c->original_deadline = original;
    c->session_deadline = session;
    wl_list_init(&c->surfaces);
    wl_list_init(&c->output_frame.link);
    c->destroy.notify = destroyed;
    c->create_surface.notify = surface_created;
    c->output_created.notify = output_created;
    c->output_destroyed.notify = output_destroyed;
    wl_signal_add(&compositor->destroy_signal, &c->destroy);
    wl_signal_add(&compositor->create_surface_signal, &c->create_surface);
    wl_signal_add(&compositor->output_created_signal, &c->output_created);
    wl_signal_add(&compositor->output_destroyed_signal, &c->output_destroyed);
    c->pixels = calloc(1, FRAME_BYTES);
    if (!c->pixels) {
        fail(c, INTERNAL);
        return -1;
    }
    weston_seat_init(&c->seat, compositor, "ci-native-input");
    c->seat_ready = true;
    if (weston_seat_init_pointer(&c->seat) < 0 ||
        init_keyboard(&c->seat) < 0) {
        fail(c, INTERNAL);
        return -1;
    }
    wl_list_for_each(output, &compositor->output_list, link)
        output_created(&c->output_created, output);
    if (c->dead)
        return -1;
    loop = wl_display_get_event_loop(compositor->wl_display);
    c->socket_source = wl_event_loop_add_fd(loop, c->fd, WL_EVENT_READABLE,
                                          socket_ready, c);
    c->timer = wl_event_loop_add_timer(loop, tick, c);
    if (!c->socket_source || !c->timer) {
        fail(c, INTERNAL);
        return -1;
    }
    if (wl_event_source_timer_update(c->timer, 10) < 0) {
        fail(c, INTERNAL);
        return -1;
    }
    /* Supervisor MUST receive this before spawning any product process.
     * exec resets dumpability, so checking its parent before exec is not enough. */
    uint32_t ready[12];
    header(c, ready, READY, OK, 0, 0, 0, 0, 0);
    if (send(c->fd, ready, sizeof ready, MSG_DONTWAIT | MSG_NOSIGNAL) != sizeof ready) {
        fail(c, DISCONNECTED);
        return -1;
    }
    return 0;
}
