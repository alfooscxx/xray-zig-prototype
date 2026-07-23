#!/usr/bin/env python3
import argparse
import asyncio
import base64
import hashlib
import ssl
import struct


WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


async def read_frame(reader):
    first, second = await reader.readexactly(2)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await reader.readexactly(8))[0]
    mask = await reader.readexactly(4) if masked else b""
    payload = bytearray(await reader.readexactly(length))
    if masked:
        for index in range(length):
            payload[index] ^= mask[index % 4]
    return opcode, bytes(payload)


def frame(opcode, payload=b""):
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header.append(length)
    elif length <= 0xFFFF:
        header.append(126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(127)
        header.extend(struct.pack("!Q", length))
    return bytes(header) + payload


async def handle_client(reader, writer):
    try:
        request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        headers = {}
        for line in request.decode("latin1").split("\r\n")[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
        key = headers.get("sec-websocket-key")
        if not key:
            return
        accept = base64.b64encode(
            hashlib.sha1((key + WEBSOCKET_GUID).encode()).digest()
        ).decode()
        writer.write(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode()
        )
        await writer.drain()

        while True:
            opcode, payload = await read_frame(reader)
            if opcode == 0x8:
                writer.write(frame(0x8, payload))
                await writer.drain()
                return
            if opcode == 0x9:
                writer.write(frame(0xA, payload))
            elif opcode in (0x1, 0x2):
                writer.write(frame(opcode, payload))
            else:
                continue
            await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19101)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    server = await asyncio.start_server(
        handle_client, args.listen, args.port, ssl=context
    )
    print(f"listening={args.listen}:{args.port}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
