// SDL3 window for Linux (X11 or Wayland), included by gfx_window.c in place of its Win32 window section: the same
// functions over the same state, so the swapchain and present code above and below it stays shared.
//
// Threads: as on Windows, a window thread owns the window and its event loop and never runs guest code; SDL video calls
// are made there only. Other threads reach it with SDL user events (settings, resize, close, clipboard) and wait for an
// answer where Windows' SendMessage would. Keyboard and mouse events go to input_win.c (input_sdl_event) and the menu
// (ui/menu_sdl.cpp) first, as WM_ messages go to their window procedure hooks.

static SDL_Window *g_win;
static uint32_t g_ev_base;               // SDL_RegisterEvents: our user events start here
enum { EV_SETTINGS, EV_RESIZE, EV_CLOSE, EV_CLIPBOARD, EV_WAKE, EV_COUNT };
static HANDLE g_sync_done;               // auto-reset event: the window thread finished a synchronous request

// ---- focus
int gfx_window_focused(void) { return g_focused; }
unsigned gfx_window_focus_messages(void) { return (unsigned)g_focus_msgs; }
HWND gfx_window_handle(void) { return (HWND)g_win; }

static int cfg_fullscreen(void) { return cfg_bool("TOTK_FULLSCREEN"); }

static void cfg_window_size(int *w, int *h) {
    int x = 0, y = 0;
    if (sscanf(cfg_value("TOTK_WINDOW_SIZE"), "%dx%d", &x, &y) != 2 || x < 640 || y < 360 || x > 7680 || y > 4320)
        sscanf(cfg_meta("WINDOW_SIZE")->def, "%dx%d", &x, &y);   // unparsable or out of range: the default
    *w = x;
    *h = y;
}

static int is_fullscreen(void) { return g_win && (SDL_GetWindowFlags(g_win) & SDL_WINDOW_FULLSCREEN) != 0; }

// Window thread. Borderless fullscreen on the window's display (SDL's desktop mode), and back.
static void toggle_fullscreen(void) {
    SDL_SetWindowFullscreen(g_win, !is_fullscreen());
    SDL_SyncWindow(g_win);
}

static char g_applied_size[32];
static int g_applied_fs;

static void note_applied(void) {
    snprintf(g_applied_size, sizeof g_applied_size, "%s", cfg_value("TOTK_WINDOW_SIZE"));
    g_applied_fs = cfg_fullscreen();
}

// TOTK_WINDOW_SIZE is in pixels; SDL sizes windows in points, which differ by the display scale (Wayland, HiDPI).
static void set_client_pixels(int cw, int ch) {
    float d = SDL_GetWindowPixelDensity(g_win);
    if (d <= 0) d = 1;
    SDL_SetWindowSize(g_win, (int)(cw / d + 0.5f), (int)(ch / d + 0.5f));
    SDL_SyncWindow(g_win);
}

// Window thread: the window takes the size and fullscreen state of the settings when they changed.
static void apply_settings(void) {
    int size_changed = strcmp(cfg_value("TOTK_WINDOW_SIZE"), g_applied_size) != 0, fs = cfg_fullscreen(),
        fs_changed = fs != g_applied_fs;
    note_applied();
    if (size_changed && !is_fullscreen()) {   // in fullscreen SDL restores the windowed size it kept
        int cw, ch;
        cfg_window_size(&cw, &ch);
        if (SDL_GetWindowFlags(g_win) & SDL_WINDOW_MAXIMIZED) SDL_RestoreWindow(g_win);
        set_client_pixels(cw, ch);
    }
    if (fs_changed && fs != is_fullscreen()) {
        input_cursor_suspend(1);
        toggle_fullscreen();
        input_cursor_suspend(0);
    }
}

static void push_user(int code, int a, int b, void *p) {
    if (!g_win) return;
    SDL_Event e = {0};
    e.type = g_ev_base + (uint32_t)code;
    e.user.code = a;
    e.user.data1 = (void *)(intptr_t)b;
    e.user.data2 = p;
    SDL_PushEvent(&e);
}

void gfx_window_apply_settings(void) { push_user(EV_SETTINGS, 0, 0, NULL); }

static void window_settings_live(void) {
    static unsigned seen;
    static int started;
    static char present[16];   // the TOTK_VK_PRESENT the swapchain was made with
    unsigned v = cfg_version();
    if (started && v == seen) return;
    seen = v;
    const char *e = cfg_value("TOTK_VK_PRESENT");
    if (!started || strncmp(e, present, sizeof present - 1)) {
        snprintf(present, sizeof present, "%s", e);
        if (started) InterlockedExchange(&g_dirty, 1);
    }
    if (started) gfx_window_apply_settings();
    started = 1;
}

void gfx_window_request_close(void) { push_user(EV_CLOSE, 0, 0, NULL); }

// ---- refresh rate of the window's display (TOTK_FPS_LIMIT=display): SDL's rational rate when it has one.
static SDL_DisplayID g_rate_disp;
static volatile LONG g_rate_mhz;   // millihertz, 0 unknown

static void refresh_rate_update(int force) {
    SDL_DisplayID d = SDL_GetDisplayForWindow(g_win);
    if (!d || (!force && d == g_rate_disp)) return;
    g_rate_disp = d;
    const SDL_DisplayMode *m = SDL_GetCurrentDisplayMode(d);
    double hz = 0;
    if (m && m->refresh_rate_denominator) hz = (double)m->refresh_rate_numerator / m->refresh_rate_denominator;
    else if (m) hz = m->refresh_rate;
    LONG mhz = (LONG)(hz * 1000 + 0.5);
    if (InterlockedExchange(&g_rate_mhz, mhz) != mhz) rt_log("gfx: monitor refresh rate %.3f Hz", hz);
}

double gfx_window_refresh_hz(void) { return InterlockedCompareExchange(&g_rate_mhz, 0, 0) / 1000.0; }

int gfx_window_monitor_size(int *w, int *h) {
    if (!g_win) return 0;
    SDL_DisplayID d = SDL_GetDisplayForWindow(g_win);
    const SDL_DisplayMode *m = d ? SDL_GetDesktopDisplayMode(d) : NULL;
    if (!m) return 0;
    float s = m->pixel_density > 0 ? m->pixel_density : 1;
    *w = (int)(m->w * s + 0.5f);
    *h = (int)(m->h * s + 0.5f);
    return 1;
}

// ---- GetForegroundWindow and GetAsyncKeyState for the files that poll the keyboard through them (input_win.c,
// flight.c): the window while it has input focus, and SDL's keyboard and mouse state by virtual key.
static SDL_Scancode vk_scancode(int vk) {
    if (vk >= 'A' && vk <= 'Z') return (SDL_Scancode)(SDL_SCANCODE_A + (vk - 'A'));
    if (vk >= '1' && vk <= '9') return (SDL_Scancode)(SDL_SCANCODE_1 + (vk - '1'));
    if (vk == '0') return SDL_SCANCODE_0;
    if (vk >= VK_NUMPAD1 && vk <= VK_NUMPAD9) return (SDL_Scancode)(SDL_SCANCODE_KP_1 + (vk - VK_NUMPAD1));
    if (vk >= VK_F1 && vk <= VK_F12) return (SDL_Scancode)(SDL_SCANCODE_F1 + (vk - VK_F1));
    switch (vk) {
    case VK_NUMPAD0: return SDL_SCANCODE_KP_0;
    case VK_SPACE: return SDL_SCANCODE_SPACE;
    case VK_TAB: return SDL_SCANCODE_TAB;
    case VK_RETURN: return SDL_SCANCODE_RETURN;
    case VK_BACK: return SDL_SCANCODE_BACKSPACE;
    case VK_ESCAPE: return SDL_SCANCODE_ESCAPE;
    case VK_SHIFT: case VK_LSHIFT: return SDL_SCANCODE_LSHIFT;
    case VK_RSHIFT: return SDL_SCANCODE_RSHIFT;
    case VK_CONTROL: case VK_LCONTROL: return SDL_SCANCODE_LCTRL;
    case VK_RCONTROL: return SDL_SCANCODE_RCTRL;
    case VK_MENU: case VK_LMENU: return SDL_SCANCODE_LALT;
    case VK_RMENU: return SDL_SCANCODE_RALT;
    case VK_CAPITAL: return SDL_SCANCODE_CAPSLOCK;
    case VK_UP: return SDL_SCANCODE_UP;
    case VK_DOWN: return SDL_SCANCODE_DOWN;
    case VK_LEFT: return SDL_SCANCODE_LEFT;
    case VK_RIGHT: return SDL_SCANCODE_RIGHT;
    case VK_INSERT: return SDL_SCANCODE_INSERT;
    case VK_DELETE: return SDL_SCANCODE_DELETE;
    case VK_HOME: return SDL_SCANCODE_HOME;
    case VK_END: return SDL_SCANCODE_END;
    case VK_PRIOR: return SDL_SCANCODE_PAGEUP;
    case VK_NEXT: return SDL_SCANCODE_PAGEDOWN;
    case VK_ADD: return SDL_SCANCODE_KP_PLUS;
    case VK_SUBTRACT: return SDL_SCANCODE_KP_MINUS;
    case VK_MULTIPLY: return SDL_SCANCODE_KP_MULTIPLY;
    case VK_DIVIDE: return SDL_SCANCODE_KP_DIVIDE;
    case VK_DECIMAL: return SDL_SCANCODE_KP_PERIOD;
    case VK_OEM_MINUS: return SDL_SCANCODE_MINUS;
    case VK_OEM_PLUS: return SDL_SCANCODE_EQUALS;
    case VK_OEM_4: return SDL_SCANCODE_LEFTBRACKET;
    case VK_OEM_6: return SDL_SCANCODE_RIGHTBRACKET;
    case VK_OEM_1: return SDL_SCANCODE_SEMICOLON;
    case VK_OEM_7: return SDL_SCANCODE_APOSTROPHE;
    case VK_OEM_COMMA: return SDL_SCANCODE_COMMA;
    case VK_OEM_PERIOD: return SDL_SCANCODE_PERIOD;
    case VK_OEM_2: return SDL_SCANCODE_SLASH;
    case VK_OEM_5: return SDL_SCANCODE_BACKSLASH;
    case VK_OEM_3: return SDL_SCANCODE_GRAVE;
    case VK_OEM_102: return SDL_SCANCODE_NONUSBACKSLASH;
    default: return SDL_SCANCODE_UNKNOWN;
    }
}

static SHORT keystate_hook(int vk) {
    if (!g_win) return 0;
    if (vk >= VK_LBUTTON && vk <= VK_XBUTTON2 && vk != 3) {
        static const int btn[] = {0, SDL_BUTTON_LEFT, SDL_BUTTON_RIGHT, 0, SDL_BUTTON_MIDDLE, SDL_BUTTON_X1, SDL_BUTTON_X2};
        return (SDL_GetMouseState(NULL, NULL) & SDL_BUTTON_MASK(btn[vk])) ? (SHORT)0x8000 : 0;
    }
    SDL_Scancode sc = vk_scancode(vk);
    int n = 0;
    const bool *ks = SDL_GetKeyboardState(&n);
    if (sc == SDL_SCANCODE_UNKNOWN || !ks || (int)sc >= n) return 0;
    int down = ks[sc];
    if (vk == VK_SHIFT) down |= ks[SDL_SCANCODE_RSHIFT];
    if (vk == VK_CONTROL) down |= ks[SDL_SCANCODE_RCTRL];
    if (vk == VK_MENU) down |= ks[SDL_SCANCODE_RALT];
    return down ? (SHORT)0x8000 : 0;
}

static HWND foreground_hook(void) {
    return g_win && (SDL_GetWindowFlags(g_win) & SDL_WINDOW_INPUT_FOCUS) ? (HWND)g_win : NULL;
}

extern int (*plat_clipboard_hook)(const char *utf8);
static int clipboard_hook(const char *utf8) {
    char *copy = strdup(utf8);
    if (!copy || !g_win) return free(copy), 0;
    push_user(EV_CLIPBOARD, 0, 0, copy);   // SDL's clipboard belongs to the window thread
    return 1;
}

// ---- window thread

static void focus_changed(int in) {
    InterlockedExchange(&g_focused, in);
    oe_set_focus(in);                          // pinned to 1 by TOTK_ASSUME_FOCUS inside
    oe_push_message(OE_MSG_FOCUS_STATE_CHANGED);
    InterlockedIncrement(&g_focus_msgs);
    if (in && g_fs_pending) {
        g_fs_pending = 0;
        if (cfg_fullscreen() && !is_fullscreen()) {
            input_cursor_suspend(1);
            toggle_fullscreen();
            input_cursor_suspend(0);
        }
    }
}

static __attribute__((noreturn)) void close_and_exit(void) {
    // The process ends with the window, once a save Commit still running in the background is done.
    rt_log("gfx: window closed; exiting");
    fs_save_flush();
    vk_pipeline_save();
    prof_write();
    ExitProcess(0);
}

static void handle_event(const SDL_Event *e) {
    if (input_sdl_event(g_win, e)) return;
    float density = SDL_GetWindowPixelDensity(g_win);
    if (menu_sdl_event(e, density > 0 ? density : 1)) return;
    if (e->type >= g_ev_base && e->type < g_ev_base + EV_COUNT) {
        switch (e->type - g_ev_base) {
        case EV_SETTINGS: apply_settings(); break;
        case EV_RESIZE:
            if (is_fullscreen()) toggle_fullscreen();
            set_client_pixels(e->user.code, (int)(intptr_t)e->user.data1);
            SetEvent(g_sync_done);
            break;
        case EV_CLOSE: close_and_exit();
        case EV_CLIPBOARD:
            SDL_SetClipboardText(e->user.data2);
            free(e->user.data2);
            break;
        case EV_WAKE: SetEvent(g_sync_done); break;
        }
        return;
    }
    switch (e->type) {
    case SDL_EVENT_KEY_DOWN:
        if (e->key.scancode == SDL_SCANCODE_F11 && !e->key.repeat) {
            input_cursor_suspend(1);
            toggle_fullscreen();
            input_cursor_suspend(0);
            cfg_set("TOTK_FULLSCREEN", is_fullscreen() ? "1" : "0");   // the menu shows it; the next start keeps it
            cfg_save();
            note_applied();
        }
        break;
    case SDL_EVENT_WINDOW_PIXEL_SIZE_CHANGED:
        InterlockedExchange(&g_dirty, 1);
        refresh_rate_update(0);
        break;
    case SDL_EVENT_WINDOW_DISPLAY_CHANGED: refresh_rate_update(0); break;
    case SDL_EVENT_DISPLAY_CURRENT_MODE_CHANGED: refresh_rate_update(1); break;
    case SDL_EVENT_WINDOW_FOCUS_GAINED: focus_changed(1); break;
    case SDL_EVENT_WINDOW_FOCUS_LOST: focus_changed(0); break;
    case SDL_EVENT_WINDOW_CLOSE_REQUESTED:
    case SDL_EVENT_QUIT: close_and_exit();
    default: break;
    }
}

static DWORD WINAPI window_main(void *arg) {
    (void)arg;
    SDL_SetHint(SDL_HINT_APP_NAME, "TotK Recomp");
    SDL_SetHint(SDL_HINT_APP_ID, "totk-recomp");               // Wayland: the .desktop file and the icon
    SDL_SetHint(SDL_HINT_VIDEO_ALLOW_SCREENSAVER, "0");
    SDL_SetHint(SDL_HINT_MOUSE_RELATIVE_MODE_CENTER, "1");
    SDL_SetHint(SDL_HINT_QUIT_ON_LAST_WINDOW_CLOSE, "0");       // WINDOW_CLOSE_REQUESTED decides
    if (!SDL_InitSubSystem(SDL_INIT_VIDEO | SDL_INIT_EVENTS)) {
        rt_log("gfx: SDL video init failed: %s", SDL_GetError());
        g_wnd_failed = 1;
        SetEvent(g_wnd_ready);
        return 1;
    }
    g_ev_base = SDL_RegisterEvents(EV_COUNT);
    int cw, ch;
    cfg_window_size(&cw, &ch);
    g_background = cfg_get("TOTK_BACKGROUND_WINDOW") && atoi(cfg_get("TOTK_BACKGROUND_WINDOW"));
    SDL_WindowFlags flags = SDL_WINDOW_VULKAN | SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIGH_PIXEL_DENSITY;
    if (g_background) flags |= SDL_WINDOW_NOT_FOCUSABLE;
    g_win = SDL_CreateWindow("TotK Recomp", cw, ch, flags);
    if (!g_win) {
        rt_log("gfx: SDL_CreateWindow failed: %s", SDL_GetError());
        g_wnd_failed = 1;
        SetEvent(g_wnd_ready);
        return 1;
    }
    set_client_pixels(cw, ch);   // pixels, whatever the display scale
    rt_log("gfx: SDL video driver %s", SDL_GetCurrentVideoDriver());
    if (!g_background) {
        // Windows opens the window behind the user's and flashes it; here the window manager places it, and the
        // fullscreen setting waits for the first focus as it does there.
        SDL_FlashWindow(g_win, SDL_FLASH_UNTIL_FOCUSED);
        g_fs_pending = cfg_fullscreen();
    }
    note_applied();
    refresh_rate_update(1);
    w32_foreground_hook = foreground_hook;
    w32_keystate_hook = keystate_hook;
    plat_clipboard_hook = clipboard_hook;
    SetEvent(g_wnd_ready);
    for (;;) {
        SDL_Event e;
        if (SDL_WaitEventTimeout(&e, 50)) {
            handle_event(&e);
            while (SDL_PollEvent(&e)) handle_event(&e);
        }
        input_sdl_tick(g_win);   // cursor capture changes asked for by other threads
    }
    return 0;
}

// ---- the window as the shared swapchain code sees it

static int wnd_minimized(void) {
    return g_win && (SDL_GetWindowFlags(g_win) & (SDL_WINDOW_MINIMIZED | SDL_WINDOW_HIDDEN)) != 0;
}

static void wnd_client_size(int *w, int *h) {
    *w = *h = 0;
    if (g_win) SDL_GetWindowSizeInPixels(g_win, w, h);
}

// Synchronous, as SetWindowPos from another thread is on Windows: the window has its new size on return.
static void wnd_set_client_size(int cw, int ch) {
    if (!g_win) return;
    push_user(EV_RESIZE, cw, ch, NULL);
    WaitForSingleObject(g_sync_done, 5000);
}

static int wnd_open(void) {
    if (g_win) return 1;
    g_wnd_failed = 0;
    g_sync_done = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_wnd_ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE t = CreateThread(NULL, 0, window_main, NULL, 0, NULL);
    if (!t) rt_fatal("gfx: cannot start the window thread (error %lu)", GetLastError());
    CloseHandle(t);
    WaitForSingleObject(g_wnd_ready, INFINITE);
    CloseHandle(g_wnd_ready);
    return !g_wnd_failed;
}

static void wnd_create_surface(VkInstance inst, VkSurfaceKHR *out) {
    if (!SDL_Vulkan_CreateSurface(g_win, inst, NULL, out))
        rt_fatal("gfx: SDL_Vulkan_CreateSurface failed: %s (the Vulkan instance needs the %s surface extension)",
                 SDL_GetError(), SDL_GetCurrentVideoDriver());
}
