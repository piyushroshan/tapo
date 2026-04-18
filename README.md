# Tapo

Manage TP-Link Tapo devices through reverse-engineered cloud APIs. Supports cameras, smart plugs, light bulbs, and other Tapo ecosystem devices.

## Features

- **Device Discovery** — list and monitor all Tapo devices on your account
- **Camera Streaming** — live view via cloud QUIC relay, converted to HLS for browser playback
- **Cloud Video Playback** — browse and play Tapo Care motion-triggered recordings
- **Local Access** — stream and access SD card recordings for devices on the same LAN
- **Event Notifications** — motion alerts and device status updates

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/getting-started/installation/)
- [ffmpeg](https://ffmpeg.org/) (must be on PATH)

## Setup

```bash
uv sync
uv run uvicorn server:app --host 0.0.0.0 --port 8000
```

Open http://localhost:8000 in your browser.

## Usage

1. Log in with your TP-Link / Tapo account credentials
2. If MFA is enabled, approve the push notification in the Tapo app and enter the code
3. Your devices will appear in the device list

## Development

```bash
uv run uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

Session state (login token, service URLs) is persisted in `tapo.db` so you don't need to re-login after restarts.
