# Linux-Defender

A lightweight Linux defense utility designed to detect risky archive behavior and warn about large files.

## Continuous monitoring (first feature)

The systemd **user service** scans configured folders every 30 seconds, including while you use the desktop. It starts automatically when you log in and logs warnings to the systemd journal. It does not need root privileges.

1. Clone this repository to `~/Linux-Defender` (or edit `WorkingDirectory` in `systemd/linux-defender.service` to the checkout location).
2. Install and start the service:

   ```bash
   mkdir -p ~/.config/systemd/user
   cp systemd/linux-defender.service ~/.config/systemd/user/
   systemctl --user daemon-reload
   systemctl --user enable --now linux-defender.service
   ```

3. View status and warnings:

   ```bash
   systemctl --user status linux-defender.service
   journalctl --user -u linux-defender.service -f
   ```

By default, it monitors `~/Downloads`, warns on files at least 100 MiB, and flags ZIP-compatible archives with at least 500 MiB expanded size, a compression ratio of 100:1 or more (for archives with at least 10 MiB expanded data), or 10,000 entries. Edit the service's `Environment=` values and run `systemctl --user daemon-reload` followed by `systemctl --user restart linux-defender.service` to change the settings. Set `LINUX_DEFENDER_WATCH_PATHS` to one or more colon-separated paths to monitor other locations.

To keep the user service running after logout, enable systemd lingering for your account with `loginctl enable-linger "$USER"` (this may require administrator approval). Without lingering, the service starts at login and stops when the user manager stops.

## Important limitations

This is periodic monitoring, not a kernel-level real-time scanner. A file can be created or used between scans. The monitor **does not extract archives or intercept extraction commands**, so it warns about suspicious archive metadata but cannot guarantee that another program will not extract one. For safer use, inspect warnings before extracting and use extraction tools with resource limits. Monitoring all of `/` is not recommended; configure specific directories you use.

The monitor uses only Python's standard library and does not execute or unpack scanned files.
