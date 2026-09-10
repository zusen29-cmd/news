import time, random, datetime
from ReQAPI import pb_encode, AES_CBC128

APP_ID = "FFD58FB4F76F648C2A5E21EBCFA3AAE81B4C9B7D97"

class GPackGEN:
    def __init__(self, logindata, jsdata):
        self.iv             = bytes(jsdata["iv"])
        self.key            = bytes(jsdata["key"])
        self.account_id     = logindata.get(str(1))
        self.account_region = jsdata["LockRegion"]
        self.account_name   = logindata.get(str(4), jsdata["UserNickName"])
        self.client_version = jsdata["ClientVersion"]

        sv_map = {s["2"].upper(): s["1"] for s in logindata["19"]}
        try:
            code = sv_map.get(self.account_region.upper(), 0)
            self.region_code = "%02X" % int(code)
        except:
            self.region_code = "00"

    def _build(self, fields):
        payload = AES_CBC128(pb_encode(dict(fields[1:])), self.key, self.iv).hex()
        length  = hex(len(payload) // 2)[2:]
        pad     = "0" * max(0, 8 - len(length))
        raw     = "%02x%s%s%s%s" % (fields[0][1], self.region_code, pad, length, payload)
        return bytes.fromhex(raw)

    def _dig_tstamp(self):
        s   = datetime.datetime.utcnow()
        nxt = s + datetime.timedelta(days=(7 - s.weekday()))
        nxt = nxt.replace(hour=6, minute=0, second=0, microsecond=0)
        return int(nxt.timestamp())

    def _voice_token(self):
        """Ghép token đúng: APP_ID + region + '_' + account_uid thật."""
        return f"{APP_ID}{self.account_region}_{self.account_id}"

    def leave_squad(self, uid=1):
        fields = {}
        fields[0] = 5
        fields[1] = 7
        fields[2] = {1: int(uid)}
        return self._build(list(fields.items()))

    def open_micro(self):
        # Device info nested
        device = {}
        device[1]  = 55
        device[2]  = 11
        device[3]  = 1
        device[4]  = "samsung"
        device[5]  = "15"
        device[6]  = 562135116
        device[7]  = {12: 7005479156896394610}
        device[8]  = ""
        device[9]  = "f848a016-d179-4915-a7e4-bfce0725d3f8"
        device[10] = APP_ID
        device[11] = "voice"
        device[12] = "SM-A145F"
        device[13] = 1
        device[14] = "s5e3830"

        packet_data = {}
        packet_data[0] = 5
        packet_data[1] = 88
        packet_data[2] = device
        packet_data[3] = 4529
        packet_data[4] = self._voice_token()   # FIX: dùng token thật
        packet_data[5] = "all"
        return self._build(list(packet_data.items()))

    def open_micro2(self):
        """Variant với token thật — giữ để tham khảo."""
        device = {}
        device[1]  = 55
        device[2]  = 11
        device[3]  = 1
        device[4]  = "samsung"
        device[5]  = "15"
        device[6]  = 562135116
        device[7]  = {12: 7005479156896394610}
        device[8]  = ""
        device[9]  = "f848a016-d179-4915-a7e4-bfce0725d3f8"
        device[10] = APP_ID
        device[11] = "voice"
        device[12] = "SM-A145F"
        device[13] = 1
        device[14] = "s5e3830"

        packet_data = {}
        packet_data[0] = 5
        packet_data[1] = 88
        packet_data[2] = device
        packet_data[3] = 4529
        packet_data[4] = self._voice_token()
        packet_data[5] = "all"
        return self._build(list(packet_data.items()))

    def join_squad(self, tc):
        fields = {}
        fields[0] = 5
        fields[1] = 4
        fields[2] = {
            4: bytes([1, 7, 9, 10, 11, 18, 25, 32, 39]),
            5: str(tc), 6: 6, 8: 1,
            9: {
                1: "08FFF3BE903F27DF0203110111110000006B0003006800169194106F13CF106E4676251411010404dfe9e8b5ca3ca4f96a3119c00000004f03060301cacfa16d",
                2: 130,
                3: "tY_S\u0013\b\u0001M\u0002\u0000T\u0000\u0005\u000e\b\t\u0002\u0000\u0003U\u0003\u0001V\u000fR\u000e\tRQ\u0002\u0004\u0005US\u0003XS\u0005\u0001\u0002\u0011\u0001\u0002JuTAEN\u001e\u0002\u001c\u0002\u001f\u0013\b\u0003M\u001cDbz_Q@}p_QOgsC\u001dYVI\u0004UAAj_ga\u0004\u0012\u0000K\u001d\u0007_t\u0019b\bCx\u0002UeGat\u001fTTCBLER`\u0006\u0001\r\f\u0012\u0006\u0005N^^\u0002acH~r\u0004_\u0003RO|\u000bcd_@~`Rnqrgh\n\u0015\nL\\Nh\u0000~G\u000et\u0000eb]VQ\u0006t^F[ZIGxCdZD\u000b\u0011\u0002OA~LP@\u000fcSDyATQApaT^{|wa]\\\u0001E\u000f\u0013\nJfxve}\u0004J\u0003c{YL\u0007^^yDYQf\bhe\u0005_wg\r\u0010\u0007\bEHpX@||\u0002Z\\uTGyA\u0001JP\u0005t~VkTE\u0000J\\\u000b\u0013\nMr\u0018zTzK}qE]vnvwROuheYvwduvQ\r\u001a\u0005M\u0006z\u001dfXfzvHFc~dXUz}O\u001aB\u0005t\u0002i\u001co_\u0004\u0012\u0003\u0007J\u0006b\u0003\u000eqlfvbEstgu~wB\u0001v@`yI\u0002ZPx\f\u0014\u0003NR\u0002yBZvuD_cd\u0004q]lH]\u0007bD}pCe\t\u0004t\n",
                4: "w^_R", 6: 11, 7: "\u0014\u0004aqrg\u0015\u0013", 8: "1.126.7", 9: 3, 10: 2,
                11: "\u0003bbSQ6wxegh9qAdV2KyoVleA17yPmYF+yTnOrl+JMknmppeUBe5ZsiHueP2mZZ4KOs6b2Ail1S9z3qIeU9hGFZ2M6PP39/zjIc/RFVPAkgDagySswMVmYaPhkzU5IqNPow2843fyQUz9xI10NdMhl1WiI4Y6wCXBotiUS9wSgujQ4j0fWXUyklCxBWo8r27hyoGSVrPdTPXFMnJJpPRRFFmWqc3fWvMg+BNfxSRJOZRSrkzG0nNvSIJ4uZB2pqAlHIPEYx7bI6zsgwUVDiLZJKTUTyuCGbOd1DegDUFfazFesTG1LJknT5WhgzCsrBIy+f2l+LeJe5DW7wEwNaHambM7ECXcJcLIhB9kJJsW0tFvXkk3HSdcQ8N1K6wjSKWhpkW0kV8Zrjj0jkhS/7AZ6T9GJRIA827YDtTorBvbx1UkXjYrqYI1nSa2GaMexGnqlurc5DE3v1R+mUBI9GqmjEPgTSYVBxyeCdQMHaMXGtspAhvkiO84ToU87sP45pylDEfFOVoc/rcmdzWeqlYPsv6txKRtIHcb0cO+MoVShoU8ZUVRDF3znbqzVrscPIfplBaa79lwvQqzRubLl9XY="
            },
            11: {1: "IDC4", 2: 281, 3: "VN"},
            13: "fr", 16: "7OR\u0019", 20: "\b\u0015", 27: "\bH\u0010\u0003"
        }
        return self._build(list(fields.items()))
