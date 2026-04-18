# Tapo Camera Stream

Web UI for TP-Link Tapo cameras — live streaming, cloud video playback, and event notifications via reverse-engineered cloud APIs.

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/getting-started/installation/)
- [ffmpeg](https://ffmpeg.org/) (must be on PATH)

## Setup

```bash
# Install dependencies
uv sync

# Run the server
uv run uvicorn server:app --host 0.0.0.0 --port 8000
```

Open http://localhost:8000 in your browser.

## Usage

1. Log in with your TP-Link / Tapo account credentials
2. If MFA is enabled, approve the push notification in the Tapo app and enter the code
3. Your cameras will appear in the device list

### Live Streaming

Select a camera and click **Start Live Stream**. Video is relayed through TP-Link's cloud via QUIC and converted to HLS for browser playback.

### Cloud Videos (Tapo Care)

Browse and play back motion-triggered recordings stored in Tapo Care. Select a camera, pick a date range, and click on a video to stream or download it.

### Local Mode

If cameras are on the same LAN, local streaming and SD card recording access is available via the Local tab.

## Development

```bash
# Run with auto-reload (note: kills active streams on code changes)
uv run uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

Session state (login token, service URLs) is persisted in `tapo.db` so you don't need to re-login after restarts.
