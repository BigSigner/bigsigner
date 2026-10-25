Below is a project-oriented summary of what we established, with the distinction between **development hardware bring-up** and the **final air-gapped SeedSigner-derived OS** kept explicit.

## Project goal

The goal is to fork both the hardware-support layer in **SeedSigner OS** and, ultimately, the UI/input layer in **SeedSigner**, so that a Raspberry Pi Zero can run as a stateless, air-gapped Bitcoin signing device using a **large ~4", 800×480 touchscreen** instead of SeedSigner’s traditional 1.3", 240×240 non-touch display.

The original SeedSigner hardware is built around a Raspberry Pi Zero, camera and **Waveshare 1.3" 240×240 LCD HAT**, with navigation through a joystick/buttons. SeedSigner still recommends the non-wireless Pi Zero 1.3 where possible, although Zero W and Zero 2 W are supported. [GitHub](https://github.com/SeedSigner/seedsigner)

The current SeedSigner application is no longer completely hard-wired to one display: its renderer obtains width/height from a display configuration and supports multiple display drivers, including ST7789, ILI9341 and ILI9486. That is useful groundwork, but a large HDMI framebuffer/KMS display will still require a new display backend and substantial UI adaptation. [GitHub](https://github.com/SeedSigner/seedsigner/blob/dev/src/seedsigner/gui/renderer.py)

## SeedSigner OS security model

The important properties worth preserving from SeedSigner OS are more important than preserving its exact current hardware configuration.

The release OS is Buildroot-based and deliberately tiny. It boots the entire root filesystem into RAM; after the SeedSigner splash screen appears, the microSD can be removed. The release OS disables networking/Bluetooth, swap, I²C, serial, USB and PWM, explicitly has **no HDMI support**, and packages the kernel/filesystem into a single read-only `zImage`. [GitHub](https://github.com/SeedSigner/seedsigner-os/blob/main/README.md?utm_source=chatgpt.com)

That means our fork should not simply turn Raspberry Pi OS into a wallet. The eventual target should retain approximately this architecture:

| Property | Original SeedSigner release | Large-touch fork target |
|---|---|---|
| Root filesystem | RAM/initramfs | Keep |
| SD removable after boot | Yes | Keep |
| Seed persisted to SD | No | Keep |
| Networking | Disabled | Keep disabled |
| Bluetooth/Wi-Fi software | Removed | Keep removed |
| Swap | Disabled | Keep disabled |
| HDMI | Disabled | **Enable** |
| SPI | Used for existing LCD | **Enable for touch** |
| Touch input/evdev | Not required | **Enable** |
| USB | Disabled | Prefer disabled in release |
| Display | Small SPI LCD | HDMI framebuffer/KMS |
| Input | GPIO joystick/buttons | Touchscreen |

This is an important architectural point: **HDMI does not require giving up the SeedSigner air-gap model.** We can selectively restore video and touchscreen input while leaving network stacks and USB disabled.

There is also a useful precedent already inside the SeedSigner ecosystem. Issue #104 documents somebody adapting SeedSigner OS for a **480×640 Waveshare touchscreen on a Pi Zero W**, while explicitly retaining `CONFIG_NET` disabled. They had to add framebuffer, DMA, touchscreen-input and bus-driver support. Their display is DPI + Goodix/I²C rather than our HDMI + XPT2046/SPI, so the exact kernel configuration differs, but the overall approach is almost exactly what this project needs. [GitHub](https://github.com/SeedSigner/seedsigner-os/issues/104?utm_source=chatgpt.com)

[SeedSigner OS touchscreen support issue #104](https://github.com/SeedSigner/seedsigner-os/issues/104?utm_source=chatgpt.com)

## Current SeedSigner OS development workflow

There is one important update to our earlier understanding: although the **release image** deliberately removes HDMI and USB, current SeedSigner OS now has dedicated **`-dev` images**.

Those development images still boot from an initramfs but add SSH, USB Ethernet gadget networking, persistent development storage, and an **HDMI console with USB keyboard/mouse support**. On Pi Zero/Zero W, USB gadget networking works through the OTG micro-USB port. The documentation explicitly warns that these images are not security hardened and must never be used with real funds. [GitHub](https://github.com/SeedSigner/seedsigner-os/blob/main/docs/dev_images.md?utm_source=chatgpt.com)

This means the cleanest development strategy is probably:

**SeedSigner OS dev image → add HDMI graphical framebuffer + touchscreen → develop UI → build a separate hardened release configuration with networking/SSH/USB removed.**

That is preferable to making Raspberry Pi OS itself the final wallet OS.

[SeedSigner OS development-image documentation](https://github.com/SeedSigner/seedsigner-os/blob/main/docs/dev_images.md?utm_source=chatgpt.com)

## Our tested display: Waveshare 4inch HDMI LCD, SKU 12030

We positively identified our hardware as:

**Waveshare 4inch HDMI LCD, SKU 12030**

It is a 4" IPS panel with a native **480×800** resolution, normally used as **800×480 landscape**, HDMI video, and a **resistive touchscreen over SPI**. Waveshare specifies all Raspberry Pi versions as supported and specifically shows use with Raspberry Pi Zero W; the Zero simply needs a Mini-HDMI cable rather than the rigid HDMI adapter used by larger Pis. [Waveshare](https://www.waveshare.com/product/raspberry-pi/displays/4inch-hdmi-lcd.htm?utm_source=chatgpt.com)

[Waveshare 4inch HDMI LCD — SKU 12030](https://www.waveshare.com/4inch-hdmi-lcd.htm?utm_source=chatgpt.com)

The hardware paths are independent:

**Video:** Pi Zero Mini-HDMI → HDMI display controller.

**Touch:** XPT2046 → SPI → GPIO.

The micro-USB connector on this particular board is explicitly labelled **Power Only**; it is not the touch data interface.

The display has a 26-pin female GPIO header that mates with pins 1–26 of the Pi Zero’s 40-pin header. The HDMI connection is separate. In our actual test setup the display and touch worked on a Pi Zero W v1.1.

## XPT2046 touchscreen

The XPT2046 is the **touch controller**, not the LCD controller. It is commonly used with 4-wire resistive touch panels of many different physical sizes.

Linux handles it through the ADS7846-compatible touchscreen driver. On our Pi, after enabling SPI and adding the ADS7846 Device Tree overlay, `evtest` successfully reported:

```text
/dev/input/event0: ADS7846 Touchscreen
```

The essential wiring/configuration we verified was based around:

```text
SPI
chip select: CS1
touch interrupt: GPIO25
```

and an overlay of the general form:

```ini
dtoverlay=ads7846,cs=1,penirq=25,...
```

After that, touch presses and continuous motion were visible through Linux evdev.

The controller is effectively a 12-bit coordinate source, so raw readings are roughly within 0–4095. On our physical panel we observed useful edge values closer to approximately **400–3800**. That variation belongs mainly to the touch panel/controller assembly, not to whether the computer is a Zero, Zero W or Zero 2 W.

The panel can detect an **ordinary finger**, but because it is resistive it requires slight pressure. It supports continuous movement, so dragging and scrolling are possible. It is essentially **single-touch**, not smartphone-style multitouch.

A virtual keyboard is feasible at 800×480, particularly with large hit targets. For the intended wallet UI, large buttons, generous spacing and slightly oversized invisible hitboxes should make the resistive screen practical.

For a product image, I would avoid mandatory calibration. Ship model-specific calibration defaults and leave an optional diagnostic/calibration screen for unusual panels. Avoid placing critical tiny controls directly against the physical edges.

## Supporting other 800×480 / 480×800 HDMI touchscreens

The software architecture should avoid hard-coding SKU 12030. Treat display and touch as separate capabilities.

An **HDMI display** should ideally just provide an 800×480 framebuffer/KMS surface. The application should not care which HDMI LCD controller is behind it.

Touch should then be an interchangeable Linux input backend:

| Touch technology | Typical interface | SeedSigner-OS consequence |
|---|---|---|
| XPT2046 resistive | SPI | Enable SPI + ADS7846 + evdev |
| Other resistive SPI | SPI | Enable corresponding kernel driver |
| Capacitive | I²C | Re-enable I²C + appropriate driver |
| Capacitive | USB HID | Enable USB/HID, larger release attack surface |

This makes our current **HDMI + SPI-touch** board quite attractive for an air-gapped appliance. We can keep USB completely disabled in the final image.

An HDMI display with **USB capacitive touch** would give a nicer smartphone-like UX, especially for scrolling and virtual keyboards, but it would require USB host/HID support in the release OS. On a Pi Zero it also consumes the single OTG data port. For a security-minimized SeedSigner derivative, SPI or I²C touch is therefore arguably cleaner.

## Application changes are separate from OS changes

There are really **two forks/workstreams**, not one.

`seedsigner-os` must make the hardware available: HDMI output/framebuffer or DRM/KMS, SPI, ADS7846/XPT2046, evdev/input support, required Raspberry Pi firmware/kernel options and Device Tree configuration.

`seedsigner` must actually use that hardware.

Current SeedSigner is conceptually designed around a tiny 240×240 display with joystick/buttons. Its renderer now supports variable display dimensions and multiple display drivers, which is encouraging, and recent releases have even added support for some **320×240** displays. [GitHub](https://github.com/SeedSigner/seedsigner/blob/dev/src/seedsigner/gui/renderer.py) But 800×480 touch is sufficiently different that simply scaling the current 240×240 UI would waste the opportunity.

A sensible new application architecture would have:

**Display backend:** add something like `FramebufferDisplayDriver` / `HDMIDisplayDriver`, implementing the existing `show_image()` interface and presenting the PIL canvas on HDMI.

**Input backend:** add a touchscreen abstraction reading Linux `evdev`, producing press/move/release coordinates.

**UI layout:** use actual `canvas_width` / `canvas_height`, not assumptions derived from 240×240. Larger typography, richer transaction details and less paging become possible.

**Touch widgets:** components know their hit rectangles; a tap invokes them directly. Dragging can drive scrolling. Do not merely emulate joystick LEFT/RIGHT/ENTER forever, although that could be a useful first prototype.

**Keyboard:** provide a dedicated touchscreen keyboard for seed/passphrase input rather than reusing the joystick word-entry UX.

The Bitcoin/Seed/PSBT logic should ideally remain largely upstream SeedSigner code; the biggest fork delta should be hardware abstraction, input handling and presentation.

## Development setup we proved works

For hardware bring-up we successfully used a **Pi Zero W v1.1 + Raspberry Pi OS Lite 32-bit/Trixie**.

USB gadget Ethernet allowed SSH from macOS without connecting the Pi's Wi-Fi. macOS Internet Sharing then gave the Pi Internet access through the USB cable for package installation. We verified SPI with:

```text
/dev/spidev0.0
/dev/spidev0.1
```

and then verified the actual touch controller using `evtest`.

That is a perfectly good **bring-up environment**, but not a production wallet environment.

For ongoing work, the newer official SeedSigner OS `--dev` target may now be better because it already provides USB SSH/debugging while keeping the Buildroot/initramfs environment much closer to the eventual release image. [GitHub](https://github.com/SeedSigner/seedsigner-os/blob/main/docs/dev_images.md?utm_source=chatgpt.com)

## Statelessness and persistence

The crucial SeedSigner property remains: seeds should exist in volatile RAM only. SeedSigner describes seeds as temporarily held in memory and wiped when power is removed; its OS architecture lets the SD card be physically removed once boot completes. [GitHub](https://github.com/SeedSigner/seedsigner?utm_source=chatgpt.com)

The Waveshare display itself does not provide normal persistent storage for framebuffer contents or touch history, so it does not undermine that model.

The Raspberry Pi itself does have OTP (one-time-programmable) memory. SeedSigner has an open issue explicitly discussing a theoretical attack in which malicious software could write key material into OTP so that it survives power loss. This is therefore a known edge case rather than something unique to our touchscreen project. [GitHub](https://github.com/SeedSigner/seedsigner/issues/390?utm_source=chatgpt.com)

[SeedSigner OTP threat discussion #390](https://github.com/SeedSigner/seedsigner/issues/390?utm_source=chatgpt.com)

## Recommended fork structure

I would structure the project as a **large-touch hardware profile**, rather than changing the existing SeedSigner targets globally:

```text
seedsigner-os
    pi0-large-touch-dev
        HDMI enabled
        SPI + ADS7846 enabled
        evdev enabled
        USB gadget + SSH enabled
        networking allowed for development only

    pi0-large-touch
        HDMI enabled
        SPI + ADS7846 enabled
        evdev enabled
        networking disabled
        Wi-Fi/Bluetooth software absent
        USB disabled
        swap disabled
        initramfs / RAM-only runtime
        removable SD after boot

seedsigner
    HDMI/framebuffer display driver
    touchscreen/evdev input driver
    800x480 responsive layout
    touch-native components
    virtual keyboard
    optional calibration/debug screen
```

That keeps the security story very easy to explain: **the fork changes the human interface, not the air-gap model**.

The two references I would investigate first before writing much code are the current SeedSigner OS development-image implementation and touchscreen issue #104. Together they already solve a surprising amount of the plumbing we originally thought we would need to invent ourselves. [GitHub](https://github.com/SeedSigner/seedsigner-os/blob/main/docs/dev_images.md?utm_source=chatgpt.com)