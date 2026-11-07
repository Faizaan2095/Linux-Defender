# Linux-Defender

A lightweight Linux defense utility designed to detect risky archive behavior and warn about large files.

## Continuous monitoring

The systemd user service scans configured folders every 30 seconds, including while you use the desktop. It starts automatically when you log in and logs warnings to the systemd journal. It does not need root privileges and never blocks downloads or extraction.

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

By default, the service monitors `~/Downloads`, skips large-file alerts for common image types, and inspects archives for excessive expansion, suspicious compression ratios, too many entries, unsafe paths, symlinks, nested archives, and executable/installer payloads. Archive inspection reads small samples from README/manifest documents and installer scripts with strict per-file and total byte limits; it does not unpack the archive or execute its contents. Script pattern matches are heuristics and may be false positives. A README and any author/creator claim are untrusted self-reported text, not proof of legitimacy.

If `clamscan` (ClamAV) is installed, the monitor also sends each changed, stable file to the local signature scanner with file/scan-size limits and a timeout. Install ClamAV and keep its virus definitions updated using your Linux distribution's package manager to enable this additional check. ClamAV is optional; without it, only the bounded static checks run. A scan-limit or scanner error is reported as inconclusive rather than clean. Set `LINUX_DEFENDER_CLAMSCAN=0` to disable it. The monitor never executes downloaded files.

Files are inspected after they appear in the watched folder and remain unchanged for two scan cycles (normally about 30 seconds after first observation). This reduces checks of in-progress downloads but is not a pre-download gate. No scanner can guarantee maximum security: signatures can miss new threats, and static heuristics can miss malicious behavior. Verify app signatures and obtain software from trusted distribution repositories/publishers before installing; do not treat README text as authentication.

Edit the service's `Environment=` values and run `systemctl --user daemon-reload` followed by `systemctl --user restart linux-defender.service` to change settings. Set `LINUX_DEFENDER_WATCH_PATHS` to one or more colon-separated paths to monitor other locations.

To keep the user service running after logout, enable lingering for your account with `loginctl enable-linger "$USER"` (this may require administrator approval). Without lingering, the service starts at login and stops when the user manager stops.

## Limitations

This is periodic warning-only monitoring, not a kernel-level real-time scanner. A file can be used between scans. The monitor does not intercept extraction or installation, and it does not certify files as safe. Use extraction tools with resource limits for suspicious archives. Monitoring all of `/` is not recommended; configure specific directories you use.

Run the built-in tests from the repository root with `python3 -m unittest discover -s tests`.
