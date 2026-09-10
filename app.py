#!/usr/bin/env python3 / GRTC Voice Bot.
#developer : @S_ZU_01
import asyncio
import threading
import time
import os
import socket
import struct
import subprocess
import opuslib
from typing import Dict, Optional, Tuple, List

from flask import Flask, request, jsonify
from ReQAPI import AES_CBC128, pb_encode, FreeFireAPI, ProtoBuf
from GPackGEN import GPackGEN

import requests
from datetime import datetime

CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

#Guest Token
def get_guest_token(uid: str, password: str) -> Tuple[Optional[str], Optional[str]]:
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.42(SM-G935F ;Android 9;en;US;app 1.128.2 2019120828;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "If-Modified-Since": datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT"),
    }
    payload = {
        "uid": uid, "password": password,
        "response_type": "token", "client_type": "2",
        "client_secret": CLIENT_SECRET, "client_id": "100067",
    }
    try:
        resp = requests.post(url, headers=headers, data=payload, timeout=10)
        data = resp.json()
        if 'access_token' in data:
            return data['access_token'], data['open_id']
        print(f"[{uid}] Token Error: {data.get('error')}")
        return None, None
    except Exception as e:
        print(f"[{uid}] Net Error: {e}")
        return None, None

def dump_hex(tag: str, data: bytes):
    print(f"\n{'='*60}")
    print(f"  {tag}  ({len(data)} bytes)")
    print(f"{'='*60}")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part  = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {i:04X}  {hex_part:<48}  |{ascii_part}|")
    print(f"{'='*60}\n")

def normalize_keys(d):
    if isinstance(d, dict):
        return {str(k): normalize_keys(v) for k, v in d.items()}
    if isinstance(d, list):
        return [normalize_keys(i) for i in d]
    return d

def parse_results(parsed_results):
    from protobuf_decoder.protobuf_decoder import Parser
    result_dict = {}
    for result in parsed_results:
        if result.field not in result_dict:
            result_dict[result.field] = []
        field_data = {}
        if result.wire_type in ["varint", "string", "bytes"]:
            field_data = result.data
        elif result.wire_type == "length_delimited":
            field_data = parse_results(result.data.results)
        result_dict[result.field].append(field_data)
    return {
        key: value[0] if len(value) == 1 else value for key, value in result_dict.items()
    }

class VoiceDispatcherGRTC:
    def __init__(self, dispatcher_ip="148.222.82.60", dispatcher_port=6674):
        self.dispatcher_ip = dispatcher_ip
        self.dispatcher_port = dispatcher_port

    def build_protobuf(self, uid: str, room_id: str, app_id: str, uuid_str: str, auth_type: int) -> bytes:
        clean_room_id = str(room_id).replace("VN_", "")
        voice_token = f"{app_id}VN_{clean_room_id}"

        device_dict = {
            1: 17, 2: 11, 3: 1, 4: "Redmi",
            5: str(uid), 6: 562135116, 7: "arm64-v8a",
            8: "", 9: uuid_str, 10: app_id,
            11: "voiceb", 12: "24094RAD4G", 13: 2, 14: "mt6855"
        }
        device_bytes = pb_encode(device_dict)

        outer_dict = {
            1: voice_token,
            2: device_bytes,
            3: auth_type,
            4: "vn"
        }
        return pb_encode(outer_dict)

    def decode_varint(self, data: bytes, start_idx: int):
        result = 0
        shift = 0
        idx = start_idx
        while True:
            b = data[idx]
            result |= (b & 0x7F) << shift
            idx += 1
            if not (b & 0x80):
                break
            shift += 7
        return result, idx

    async def get_voice_server(self, uid: str, room_id: str, app_id: str, uuid_str: str):
        print(f"\n[STEP 2] Kết nối Dispatcher {self.dispatcher_ip}:{self.dispatcher_port} (UDP)...")
        try:
            pb_payload = self.build_protobuf(uid, room_id, app_id, uuid_str, auth_type=2)

            # TCP
            reader, writer = await asyncio.open_connection(
                self.dispatcher_ip, self.dispatcher_port
            )
            writer.write(struct.pack(">I", len(pb_payload)) + pb_payload)
            await writer.drain()
            print(f"[STEP 2] TX {len(pb_payload)}B")

            try:
                resp_len_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
            except asyncio.TimeoutError:
                print("[STEP 2] ❌ Timeout — token/room_id hết hạn?")
                return None, None
            except asyncio.IncompleteReadError:
                print("[STEP 2] ❌ Server đóng kết nối — gói sai?")
                return None, None

            resp_len = struct.unpack(">I", resp_len_bytes)[0]
            data     = await reader.readexactly(resp_len)
            print(f"[STEP 2] RX {resp_len}B")
            writer.close()
            await writer.wait_closed()

            voice_ip, voice_tcp_port = None, None
            idx = 0
            if idx < len(data) and data[idx] == 0x0A:
                idx += 1; ip_len = data[idx]; idx += 1
                voice_ip = data[idx:idx+ip_len].decode("utf-8"); idx += ip_len
            if idx < len(data) and data[idx] == 0x10:
                idx += 1; voice_tcp_port, _ = self.decode_varint(data, idx)

            if not voice_ip:
                print("[STEP 2] ❌ Không parse được IP:port")
                return None, None

            print(f"[✅ STEP 2] voice_ip={voice_ip}  tcp_port={voice_tcp_port}")
            return voice_ip, voice_tcp_port
        except Exception as e:
            print(f"[❌ STEP 2] Lỗi Dispatcher: {repr(e)}")
            return None, None

#TCP HANDSHAKE
class VoiceTCPHandshakeGRTC:
    def __init__(self, voice_ip: str, voice_tcp_port: int):
        self.voice_ip = voice_ip
        self.voice_tcp_port = voice_tcp_port

    def build_f9_auth_packet(self, uid: str, room_id: str, app_id: str, uuid_str: str) -> bytes:
        clean_room_id = str(room_id).replace("VN_", "")
        voice_token = f"{app_id}VN_{clean_room_id}"

        device_dict = {
            1: 7, 2: 11, 3: 1, 4: "Redmi",
            5: str(uid), 6: 562135116, 7: "arm64-v8a",
            8: "", 9: uuid_str, 10: app_id,
            11: "voiceb", 12: "24094RAD4G", 13: 2, 14: "mt6855"
        }
        device_bytes = pb_encode(device_dict)

        outer_dict = {
            1: device_bytes,
            2: voice_token,
            10: 1,
            11: str(uid),
            12: 0,
            14: 0,
            16: 1
        }
        return pb_encode(outer_dict)

    def decode_varint(self, data: bytes, start_idx: int):
        result = 0
        shift = 0
        idx = start_idx
        while idx < len(data):
            b = data[idx]
            result |= (b & 0x7F) << shift
            idx += 1
            if not (b & 0x80): break
            shift += 7
        return result, idx

    async def execute_handshake(self, uid: str, room_id: str, app_id: str, uuid_str: str):
        print(f"\n[STEP 3] Đang kết nối TCP tới VOICE SERVER {self.voice_ip}:{self.voice_tcp_port}...")
        try:
            reader, writer = await asyncio.open_connection(self.voice_ip, self.voice_tcp_port)
            
            pb_payload = self.build_f9_auth_packet(uid, room_id, app_id, uuid_str)
            writer.write(struct.pack(">I", len(pb_payload)) + pb_payload)
            await writer.drain()

            #Auth response (~35 bytes) ──
            resp1_len_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
            resp1_len = struct.unpack(">I", resp1_len_bytes)[0]
            resp1_payload = await reader.readexactly(resp1_len)

            # Parse toàn bộ fields từ RESP-1
            udp_port, ssrc = None, None
            fields_r1 = {}
            idx = 0
            while idx < len(resp1_payload):
                tag_type = resp1_payload[idx]; idx += 1
                field_num = tag_type >> 3
                wire_type = tag_type & 0x07
                if wire_type == 0:
                    val, idx = self.decode_varint(resp1_payload, idx)
                    fields_r1[field_num] = val
                elif wire_type == 2:
                    length, idx = self.decode_varint(resp1_payload, idx)
                    raw = resp1_payload[idx:idx+length]; idx += length
                    fields_r1[field_num] = raw
                else: break

            # UDP port: field 2
            udp_port = fields_r1.get(2) or fields_r1.get(5)

            f13 = fields_r1.get(13, 0)
            f13_32 = f13 & 0xFFFFFFFF
            f3 = fields_r1.get(3, 0)

            if f13_32 > 0:
                ssrc = f13_32
            elif f3 > 0:
                ssrc = f3
            else:
                import random
                ssrc = random.randint(0x10000000, 0x7FFFFFFF)

            f3_val = f3 & 0xFFFFFFFF   # fixed_2 = field[3] từ RESP-1
            print(f"[STEP3] UDP={udp_port} SSRC=0x{ssrc:08X} fixed_2=0x{f3_val:08X}")

            #TX CUSTOM BINARY: Echo field 1 (SSRC candidate) về server
            f1_raw = fields_r1.get(1, b"")
            if f1_raw:
                custom_pb = bytes([0x0A, len(f1_raw)]) + f1_raw  # field1 type=bytes
            else:
                custom_pb = resp1_payload  # fallback: echo toàn bộ
            custom_bin = struct.pack(">I", len(custom_pb)) + custom_pb
            print(f"[STEP3] TX echo field1 ({len(custom_bin)}b)")
            writer.write(custom_bin)
            await writer.drain()

            #RESP-2: Server confirm ready
            try:
                resp2_len_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
                resp2_len = struct.unpack(">I", resp2_len_bytes)[0]
                resp2_payload = await reader.readexactly(resp2_len)
                print(f"[✅ STEP3] Server READY ({len(resp2_payload)}b)")
            except asyncio.TimeoutError:
                print("[\u26a0\ufe0f STEP3] Timeout RESP-2 — tiếp tục")

            print(f"[✅ STEP 3] UDP={udp_port} | SSRC={hex(ssrc)} | fixed_2=0x{f3_val:08X}")
            return udp_port, ssrc, f3_val, reader, writer
        except Exception as e:
            print(f"[\u274c STEP 3] Lỗi Handshake: {repr(e)}")
            import traceback; traceback.print_exc()
            return None, None, None, None

#OPUS UDP STREAM
class OpusVoiceClientGRTC:
    def __init__(self, voice_ip: str, voice_udp_port: int, ssrc: int, fixed_2: int = 0x00002662):
        self.voice_ip = voice_ip
        self.voice_udp_port = voice_udp_port
        self.ssrc = ssrc
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2.0)
        self.is_running = False
        
        # toc=0x48 / SILK NB 8kHz 20ms
        self.encoder = opuslib.Encoder(48000, 1, opuslib.APPLICATION_AUDIO)
        self.sample_rate = 48000
        self.frame_size = 960  # 960 samples * 1ch = 20ms @ 8kHz
        self.seq_num   = 1
        self.timestamp = 0
        self.fixed_2   = fixed_2
        print(f"[OpusClient] voice={voice_ip}:{voice_udp_port} ssrc=0x{ssrc:08x} fixed_2=0x{fixed_2:08x}")

    def send_open_mic(self, ka_seq=None, ka_ts=None):
        # Dùng seq/ts riêng cho keepalive để không ảnh hưởng audio stream
        seq = ka_seq if ka_seq is not None else (self.seq_num & 0xFFFFFF)
        ts  = ka_ts  if ka_ts  is not None else (self.timestamp & 0xFFFFFFFF)
        pkt = bytearray()
        pkt.append(0x71)
        pkt += (seq & 0xFFFFFF).to_bytes(3, 'big')
        pkt += struct.pack(">I", ts & 0xFFFFFFFF)
        pkt += struct.pack(">I", self.ssrc & 0xFFFFFFFF)
        pkt += struct.pack(">I", 0x00000311)
        pkt += bytes.fromhex("0000010720210000286e4672656520466972650000000000000000000000")
        pkt += bytes.fromhex("e7877176")
        self.sock.sendto(bytes(pkt), (self.voice_ip, self.voice_udp_port))
        if ka_seq is None:  # Chỉ tăng nếu là mic-open khởi tạo
            self.seq_num   += 1
            self.timestamp += 960  # 48kHz frame

    def build_opus_packet(self, opus_data: bytes) -> bytes:
        header = bytearray()
        header.extend(b"\x41\x6f")
        header.extend(struct.pack(">H", self.seq_num & 0xFFFF))
        header.extend(struct.pack(">I", self.timestamp & 0xFFFFFFFF))
        header.extend(struct.pack(">I", self.ssrc & 0xFFFFFFFF))
        header.extend(struct.pack(">I", self.fixed_2 & 0xFFFFFFFF))
        self.seq_num   += 1
        self.timestamp += 960  # 48kHz frame
        return bytes(header) + opus_data

    def start_music_stream(self, mp3_file="s1.mp3", on_finish=None):
        self.is_running = True
        self._on_finish = on_finish
        print("[STEP 4] Mở Mic UDP...")
        for _ in range(3):
            self.send_open_mic()
            time.sleep(0.02)
        threading.Thread(
            target=self.audio_stream_loop,
            args=(mp3_file, on_finish),
            daemon=True
        ).start()
        threading.Thread(target=self.udp_keepalive_loop, daemon=True).start()

    def send_udp_ping(self, seq, ts):
        pkt = bytearray()
        pkt.append(0x71)
        pkt += (seq & 0xFFFFFF).to_bytes(3, 'big')
        pkt += struct.pack(">I", ts & 0xFFFFFFFF)
        pkt += struct.pack(">I", self.ssrc & 0xFFFFFFFF)
        pkt += struct.pack(">I", 0x00002662)  # fixed
        try:
            self.sock.sendto(bytes(pkt), (self.voice_ip, self.voice_udp_port))
        except Exception:
            pass

    def udp_keepalive_loop(self):
        print("[UDP KA] Start (2s/lần)")
        ka_seq = 0xF00000
        ka_ts  = 0x74000000
        ping_count = 0
        while self.is_running:
            time.sleep(2.0)
            try:
                self.send_udp_ping(ka_seq, ka_ts)
                ping_count += 1
                if ping_count % 30 == 0:
                    print(f"[UDP KA] Ping #{ping_count}")
                ka_seq = (ka_seq + 1) & 0xFFFFFF
                ka_ts  = (ka_ts + 960) & 0xFFFFFFFF
            except Exception as e:
                print(f"[UDP KA] Lỗi: {e}")

    def _load_opus_frames(self, mp3_file: str) -> list:
        """Pre-decode toàn bộ MP3 → list Opus frames trước khi stream.
        Chạy ffmpeg một lần duy nhất với communicate() → không bao giờ deadlock pipe.
        """
        cmd = [
            'ffmpeg', '-i', mp3_file,
            '-filter:a', 'volume=4.8,alimiter=limit=0.95',
            '-f', 's16le', '-ac', '1', '-ar', '48000',
            '-loglevel', 'quiet', 'pipe:1'
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pcm_data, _ = proc.communicate()   # đọc hết một lần, không block pipe
        proc.wait()

        frames = []
        chunk_size = 1920  # 960 samples * 2 bytes (s16le) * 1ch
        for i in range(0, len(pcm_data) - chunk_size + 1, chunk_size):
            raw = pcm_data[i:i + chunk_size]
            # Bỏ qua frame im lặng hoàn toàn
            if not any(raw[j] | raw[j + 1] for j in range(0, min(len(raw), 64), 2)):
                continue
            try:
                frames.append(self.encoder.encode(raw, 960))
            except Exception as e:
                print(f"[Encode] frame {i//chunk_size} lỗi: {e}")
        return frames

    @staticmethod
    def _precise_sleep(seconds: float):
        """Hybrid sleep: OS sleep đến khi còn 2ms, busy-wait phần còn lại.
        Giảm jitter từ ±30ms (time.sleep thuần) xuống <1ms.
        """
        if seconds <= 0:
            return
        deadline = time.perf_counter() + seconds
        # OS sleep cho phần lớn thời gian (trừ 2ms cuối)
        coarse = seconds - 0.002
        if coarse > 0:
            time.sleep(coarse)
        # Busy-wait 2ms cuối để đảm bảo accuracy
        while time.perf_counter() < deadline:
            pass

    def audio_stream_loop(self, mp3_file: str, on_finish=None):
        print(f"[Audio] Pre-decoding {mp3_file}...")
        frames = self._load_opus_frames(mp3_file)
        if not frames:
            print("[Audio] Không decode được frames → dừng")
            self.is_running = False
            if on_finish:
                try: on_finish()
                except Exception as e: print(f"[Audio] on_finish error: {e}")
            return
        print(f"[Audio] {len(frames)} frames loaded ({len(frames)*0.02:.1f}s) → stream bắt đầu")

        packets_sent = 0
        next_send    = time.perf_counter()

        try:
            for opus_data in frames:
                if not self.is_running:
                    break

                packet = self.build_opus_packet(opus_data)
                try:
                    self.sock.sendto(packet, (self.voice_ip, self.voice_udp_port))
                except OSError as e:
                    print(f"[Audio Loop] Socket warn: {e}")

                packets_sent += 1
                if packets_sent % 500 == 0:
                    print(f"  [Audio] {packets_sent}/{len(frames)} frames")

                next_send += 0.020
                sleep_for  = next_send - time.perf_counter()
                if sleep_for < -0.040:
                    # Bị trễ quá 40ms → reset để tránh burst frames dồn cục
                    next_send = time.perf_counter()
                elif sleep_for > 0:
                    self._precise_sleep(sleep_for)

            print(f"[Audio Loop] Hết nhạc sau {packets_sent} frames → dừng")

        except Exception as e:
            print(f"[Audio Loop] Fatal: {e}")
            import traceback; traceback.print_exc()
        finally:
            self.is_running = False
            if on_finish:
                try:
                    on_finish()
                except Exception as e:
                    print(f"[Audio Loop] on_finish error: {e}")


#PIPELINE TRIGGER
def trigger_music_pipeline(bot, gvoice_room_id, gvoice_squad_id):
    def _start_music():
        time.sleep(0.5)
        _uuid   = getattr(bot.pgen, 'uuid',   None) or "682761f7-3f39-4912-b019-ced851732362"
        _app_id = getattr(bot.pgen, 'app_id', None) or "FFD58FB4F76F648C2A5E21EBCFA3AAE81B4C9B7D97"
        _uid    = bot.account_uid
        
        loop = asyncio.new_event_loop()  # loop

        async def master_voice_pipeline():
            print(f"[PIPELINE] Bắt đầu GRTC. Room: {gvoice_room_id}")
            
            #HÀM ĐÓNG GÓI CHUẨN CHO TẤT CẢ CMD (9, 11, 24, 33, 35)
            async def send_tcp_cmd(writer, cmd_id):
                try:
                    clean_room_id = str(gvoice_room_id).replace("VN_", "")
                    voice_token = f"{_app_id}VN_{clean_room_id}"
                    
                    # Field 1 chứa mã CMD
                    f1_bytes = pb_encode({1: cmd_id, 2: 0, 3: 0})
                    f3_bytes = pb_encode({1: str(_uid), 2: 1})
                    payload = pb_encode({1: f1_bytes, 2: voice_token, 3: f3_bytes})
                    
                    writer.write(struct.pack(">I", len(payload)) + payload)
                    await writer.drain()
                    print(f"  [TCP TX] Đã gửi CMD={cmd_id}")
                except Exception as e:
                    print(f"  [TCP TX] Lỗi CMD={cmd_id}: {e}")

            # --- GÓI AGORA JOIN (GỬI THUẦN HEX) ---
            async def send_agora_join(writer):
                try:
                    agora_pkt = bytes.fromhex("feffff7f")
                    writer.write(struct.pack(">I", len(agora_pkt)) + agora_pkt)
                    await writer.drain()
                    print("  [TCP TX] Đã gửi AGORA_JOIN (FE FF FF 7F)")
                except Exception: pass

            # THỰC THI TIMELINE CHUẨN
            dispatcher = VoiceDispatcherGRTC() 
            voice_ip, voice_tcp_port = await dispatcher.get_voice_server(_uid, gvoice_room_id, _app_id, _uuid)
            if not voice_ip or not voice_tcp_port: return

            await asyncio.sleep(0.1)
            handshake = VoiceTCPHandshakeGRTC(voice_ip, voice_tcp_port)
            udp_port, ssrc, fixed_2, v_reader, v_writer = await handshake.execute_handshake(_uid, gvoice_room_id, _app_id, _uuid)
            if not udp_port or not ssrc: return

            print("[PIPELINE] Đồng bộ Game Server...")
            
            await send_tcp_cmd(v_writer, 9)
            await asyncio.sleep(0.05)
            await send_agora_join(v_writer)
            
            #UDP send 0x71 (open_mic)
            opus_client = OpusVoiceClientGRTC(voice_ip=voice_ip, voice_udp_port=udp_port, ssrc=ssrc, fixed_2=fixed_2)
            opus_client.send_open_mic() 
            await asyncio.sleep(0.1)

            await send_tcp_cmd(v_writer, 24)
            await send_tcp_cmd(v_writer, 35)

            # LUỒNG GIỮ MẠNG
            async def tcp_reader_and_keepalive():
                last_cmd9_time = time.time()
                music_started  = False

                while not v_writer.is_closing():
                    current_time = time.time()
                    if current_time - last_cmd9_time >= 18:
                        await send_tcp_cmd(v_writer, 9)
                        print(f"  [TCP KA] CMD=9 start_speak (keepalive)")
                        last_cmd9_time = current_time
                    phase = "header"
                    pay_len = 0
                    try:
                        hdr = await asyncio.wait_for(v_reader.readexactly(4), timeout=1.0)
                        pay_len = struct.unpack(">I", hdr)[0]

                        # FIX TCP DESYNC
                        if pay_len == 0:
                            continue
                        if pay_len > 500_000:
                            print(f"[TCP Loop] pay_len bat thuong ({pay_len} bytes = 0x{pay_len:08X}), ngat")
                            break

                        phase = "payload"
                        payload = await asyncio.wait_for(
                            v_reader.readexactly(pay_len),
                            timeout=10.0
                        )
                        phase = "done"
                        print(f"  [TCP RX] {pay_len}B")

                        # Parse CMD từ server
                        cmd_id = None
                        if len(payload) >= 3 and payload[0] == 0x0a:
                            inner_len = payload[1]
                            if inner_len >= 2 and payload[2] == 0x08:
                                cmd_id = payload[3] if len(payload) > 3 else None

                        # 1. Nếu là gói to (> 100 bytes) -> Member Info -> Kích nhạc
                        if pay_len > 100 and not music_started:
                            print("  [RX] Member Info → kích nhạc")
                            await send_agora_join(v_writer)
                            await send_tcp_cmd(v_writer, 33)
                            music_started = True
                            if not getattr(opus_client, 'is_running', False):
                                def _on_music_finish():
                                    """Khi hết nhạc: đóng TCP voice, reset bot."""
                                    print("[FINISH] Nhạc xong → bot sẵn sàng nhận TC mới")
                                    try:
                                        opus_client.is_running = False
                                        try:
                                            v_writer.close()
                                        except Exception:
                                            pass
                                    except Exception as e:
                                        print(f"[FINISH] Error: {e}")
                                    finally:
                                        bot.busy = False
                                opus_client.start_music_stream("s1.mp3", on_finish=_on_music_finish)

                        elif cmd_id == 11:
                            await send_tcp_cmd(v_writer, 11)
                        elif cmd_id == 10 or b"\x08\x0a" in payload[:15]:
                            await send_tcp_cmd(v_writer, 11)
                        else:
                            if cmd_id:
                                print(f"  [RX] CMD={cmd_id} (bỏ qua)")

                    except asyncio.TimeoutError:
                        if phase == "payload":
                            print(f"[TCP Loop] Timeout doc payload (pay_len={pay_len}), ngat")
                            break
                    except Exception as e:
                        print(f"\n[TCP Loop] Server ngat ket noi: {e}")
                        print("[TCP Loop] Thử renew mic session...")
                        try:
                            # Gửi lại mic-open UDP để renew session
                            for _ in range(3):
                                opus_client.send_open_mic()
                                time.sleep(0.05)
                        except Exception:
                            pass
                        break

            await tcp_reader_and_keepalive()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(master_voice_pipeline())        
    threading.Thread(target=_start_music, daemon=True).start()

def try_parse_voice_info(data: bytes, bot):
    if len(data) <= 3: return
    from protobuf_decoder.protobuf_decoder import Parser

    def find_squad_and_room(data_dict):
        if isinstance(data_dict, dict):
            if "5" in data_dict and isinstance(data_dict["5"], dict):
                f5 = data_dict["5"]
                s_id = f5.get("1") or data_dict.get("1")
                for try_key in ["14", "31", "33", "17", "16", "20"]:
                    r_id = f5.get(try_key)
                    if r_id and s_id:
                        r_id_str = str(r_id)
                        for pfx in ["VN_", "BB_", "IDC1_"]:
                            if r_id_str.startswith(pfx):
                                r_id_str = r_id_str[len(pfx):]
                                break
                        return s_id, r_id_str
            for k, v in data_dict.items():
                res = find_squad_and_room(v)
                if res[0] is not None: return res
        elif isinstance(data_dict, list):
            for item in data_dict:
                res = find_squad_and_room(item)
                if res[0] is not None: return res
        return None, None

    for header_len in range(3, 7):
        payload = data[header_len:]
        if not payload: continue
        try:
            pb = ProtoBuf(payload)
            parsed_data = pb.protobuf()
            squad_id, room_id_raw = find_squad_and_room(parsed_data)
            
            if room_id_raw:
                room_id = "VN_" + str(room_id_raw)
                print(f"[SCANNER] Room ID: {room_id}")
                trigger_music_pipeline(bot, room_id, squad_id)
                return
        except Exception: pass

#
async def host_and_invite_once(bot, team_code: str):
    bot.run_count = getattr(bot, 'run_count', 0) + 1
    uid = bot.uid

    try:
        if not bot.online_writer or bot.online_writer.is_closing():
            return False, "Writer đã đóng"
        if not bot.is_online:
            return False, "Bot không online"

        while not bot.packet_queue.empty():
            try: bot.packet_queue.get_nowait()
            except: break

        # JOIN TEAMCODE
        join_pkt = bot.pgen.join_squad(team_code)
        bot.online_writer.write(join_pkt)
        await bot.online_writer.drain()

        print(f"[{uid}] Đã gửi join, chờ response (5s)...")
        gvoice_room_id = None
        gvoice_squad_id = None

        try:
            join_resp = await asyncio.wait_for(bot.packet_queue.get(), timeout=5.0)
            from protobuf_decoder.protobuf_decoder import Parser
            try:
                for hdr in range(3, 7):
                    try:
                        jr_raw = parse_results(Parser().parse(join_resp[hdr:].hex()))
                        jr = normalize_keys(jr_raw)
                        if "5" in jr and isinstance(jr["5"], dict):
                            f5 = jr["5"]
                            sq = f5.get("1")
                            for rk in ["17", "14", "31", "33"]:
                                rv = f5.get(rk)
                                if rv and (isinstance(rv, (int, str))):
                                    rv_str = str(rv)
                                    # Bỏ prefix nếu có
                                    for _pfx in ["VN_", "BB_", "IDC1_"]:
                                        if rv_str.startswith(_pfx):
                                            rv_str = rv_str[len(_pfx):]
                                            break
                                    if rv_str.isdigit() or "_" in rv_str:
                                        gvoice_room_id  = "VN_" + rv_str
                                        gvoice_squad_id = sq
                                        print(f"  [JOIN] room_id={gvoice_room_id} (field5.{rk})")
                                        break
                            if gvoice_room_id: break
                    except Exception: continue
            except Exception as je:
                pass

            if not gvoice_room_id:
                try_parse_voice_info(join_resp, bot)

        except asyncio.TimeoutError:
            print(f"[{uid}] ⚠️ Timeout 5s — không nhận được join response")

        if gvoice_room_id and gvoice_squad_id:
            print(f"[{uid}] Trigger GRTC Pipeline (room={gvoice_room_id})")
            trigger_music_pipeline(bot, gvoice_room_id, gvoice_squad_id)

        # Leave squad ngay sau khi lấy được room_id
        await asyncio.sleep(0.5)
        leave_pkt = bot.pgen.leave_squad()
        bot.online_writer.write(leave_pkt)
        await bot.online_writer.drain()
        print(f"[{uid}] Leave squad")

        return True, f"Join + leave done."

    except Exception as e:
        return False, str(e)

#BotInstance
class BotInstance:
    def __init__(self, uid: str, password: str):
        self.uid = uid
        self.password = password
        self.key = None
        self.iv = None
        self.token = None
        self.account_uid = None
        self.region = None
        self.online_writer = None
        self.online_reader = None
        self.keepalive_task = None
        self.reconnect_task = None
        self._read_task = None
        self.is_online = False
        self.busy = False
        self.cooldown_until = 0
        self.lock = asyncio.Lock()
        self._stop_reconnect = False
        self.packet_queue = asyncio.Queue()
        self.run_count = 0
        self.pgen = None

    async def _safe_close_connection(self):
        if self._read_task and not self._read_task.done():
            self._read_task.cancel()
            try: await asyncio.wait_for(asyncio.shield(self._read_task), timeout=2.0)
            except: pass
        self._read_task = None
        if self.online_writer and not self.online_writer.is_closing():
            try:
                self.online_writer.close()
                await asyncio.wait_for(self.online_writer.wait_closed(), timeout=3.0)
            except: pass
        self.online_writer = None
        self.online_reader = None

    async def login_and_connect(self):
        await self._safe_close_connection()

        access_token, open_id = await asyncio.get_event_loop().run_in_executor(
            None, get_guest_token, self.uid, self.password
        )
        if not access_token or not open_id: raise Exception("get_guest_token failed")

        def _do_auth():
            api = FreeFireAPI()
            return api.get(f"{self.uid}:{self.password}")

        login_result = await asyncio.get_event_loop().run_in_executor(None, _do_auth)
        if not login_result or login_result == "account not found":
            raise Exception("FreeFireAPI auth failed")

        self.account_uid = login_result["UserAccountUID"]
        self.region = login_result["LockRegion"]
        online_ip   = login_result["GameServerAddress"]["onlineip"]
        online_port = login_result["GameServerAddress"]["onlineport"]
                
        auth_packet = bytes(login_result["UserAuthPacket"])
        logindata   = login_result["logindata"]

        jsdata = {
            "iv": login_result["iv"],
            "key": login_result["key"],
            "LockRegion": self.region,
            "UserNickName": login_result["UserNickName"],
            "ClientVersion": login_result["ClientVersion"],
        }
        self.pgen = GPackGEN(logindata, jsdata)

        reader, writer = await asyncio.open_connection(online_ip, int(online_port))
        writer.write(auth_packet)
        await writer.drain()
        self.online_reader = reader
        self.online_writer = writer
        await asyncio.sleep(3.0)
        self.is_online = True
        print(f"[{self.uid[:8]}] TCP connected ✅")

        self._read_task     = asyncio.create_task(self._read_responses())
        self.keepalive_task = asyncio.create_task(self._delayed_keep_alive())

    async def _delayed_keep_alive(self):
        await asyncio.sleep(10)
        while self.is_online:
            try:
                # Chỉ giữ vòng lặp ngủ để duy trì Task
                await asyncio.sleep(25)
            except Exception as e:
                print(f"[{self.uid[:8]}] Lỗi KeepAlive Game: {e}")
                self.is_online = False
                break

    async def _read_responses(self):
        try:
            while self.is_online:
                try:
                    data = await self.online_reader.read(65535)
                    if not data:
                        self.is_online = False
                        break
                    await self.packet_queue.put(data)
                except asyncio.CancelledError: raise
                except Exception:
                    self.is_online = False
                    break
        except asyncio.CancelledError: pass

    async def _reconnect_loop(self):
        backoff = 5
        while not self._stop_reconnect:
            if not self.is_online and not self.busy:
                await asyncio.sleep(backoff)
                if self.busy: continue
                try:
                    await self.login_and_connect()
                    backoff = 5
                except Exception as e:
                    backoff = min(backoff * 2, 60)
            await asyncio.sleep(5)

    async def start(self):
        await self.login_and_connect()
        self._stop_reconnect = False
        self.reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def close(self):
        self._stop_reconnect = True
        self.is_online = False
        if self.keepalive_task: self.keepalive_task.cancel()
        if self.reconnect_task: self.reconnect_task.cancel()
        await self._safe_close_connection()

    def is_available(self) -> bool:
        # Safety timeout 10 phút
        if self.busy and hasattr(self, '_busy_start_time') and time.time() - self._busy_start_time > 600:
            self.busy = False
        return self.is_online and not self.busy and time.time() >= self.cooldown_until

    async def run_host_bot(self, team_code: str) -> Tuple[bool, str]:
        async with self.lock:
            if self.busy: return False, "Bot Đang Bận Phát Nhạc Cho Team Khác Quay Lại Sau"
            self.busy = True
            self._busy_start_time = time.time()
        try:
            success, msg = await host_and_invite_once(self, team_code)
            if not success:
                self.busy = False
            return success, msg
        except Exception as e:
            self.busy = False
            return False, str(e)


#AccountManager
class AccountManager:
    def __init__(self, accounts_file: str = "accounts.txt"):
        self.bots: List[BotInstance] = []
        self._rr_index = 0  # round-robin index
        self.load_accounts(accounts_file)

    def load_accounts(self, filename: str):
        if not os.path.exists(filename): return
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or ':' not in line: continue
                uid, pw = line.split(':', 1)
                self.bots.append(BotInstance(uid.strip(), pw.strip()))

    async def start_all(self):
        tasks = [bot.start() for bot in self.bots]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        online = sum(1 for b in self.bots if b.is_online)
        print(f"[Manager] {online}/{len(self.bots)} bot online")

    async def get_available_bot(self) -> Optional[BotInstance]:
        n = len(self.bots)
        for i in range(n):
            bot = self.bots[(self._rr_index + i) % n]
            if bot.is_available():
                self._rr_index = (self._rr_index + i + 1) % n
                return bot
        return None

    def status(self) -> Dict:
        total   = len(self.bots)
        online  = sum(1 for b in self.bots if b.is_online)
        busy    = sum(1 for b in self.bots if b.busy)
        free    = sum(1 for b in self.bots if b.is_available())
        return {"total": total, "online": online, "busy": busy, "free": free}

    async def invite_and_host(self, team_code: str) -> Dict:
        bot = await self.get_available_bot()
        if not bot:
            st = self.status()
            if st["online"] == 0:
                return {"success": False, "message": "Không có bot nào online"}
            # Tất cả bot online đều đang bận
            return {
                "success": False,
                "message": f"Bot Đang Bận Phát Nhạc Cho Team Khác Quay Lại Sau ({st['busy']}/{st['online']} bot đang bận)"
            }
        success, msg = await bot.run_host_bot(team_code)
        return {"success": success, "message": msg}


#Flask API.
app = Flask(__name__)
manager = None
loop = None

def run_async(coro):
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result()

@app.route('/join', methods=['GET'])
def join_endpoint():
    team_code = request.args.get('tc')
    if not team_code or not team_code.isdigit():
        return jsonify({"success": False, "message": "Thiếu tc hoặc tc không hợp lệ"}), 400
    result = run_async(manager.invite_and_host(team_code))
    return jsonify(result)

@app.route('/status', methods=['GET'])
def status_endpoint():
    return jsonify(manager.status())

def start_flask():
    app.run(host='0.0.0.0', port=26320, debug=False, use_reloader=False)


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    manager = AccountManager("accounts.txt")
    loop.run_until_complete(manager.start_all())
    threading.Thread(target=start_flask, daemon=True).start()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        for bot in manager.bots:
            loop.run_until_complete(bot.close())
