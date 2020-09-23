#!/usr/bin/env python3
import asyncio
from multiprocessing import Process

from scapy.all import *
import math

# ip = "36.25.242.52"

prbWindowSz = [1, 63, 4, 4, 16, 512, 3, 128, 256, 1024, 31337, 32768, 65535]

prbOpts = [
    [('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b'')],
    [('MSS', 1400), ('WScale', 0), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('EOL', None)],
    [('Timestamp', (0xFFFFFFFF, 0)), ('NOP', None), ('NOP', None), ('WScale', 5), ('NOP', None), ('MSS', 640)],
    [('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)],
    [('MSS', 536), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)],
    [('MSS', 265), ('SAckOK', b''), ('Timestamp', (0xFFFFFFFF, 0))],
    [('WScale', 10), ('NOP', None), ('MSS', 1460), ('SAckOK', b''), ('NOP', None), ('NOP', None)],
    [('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b'')],
    [('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b'')],
    [('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b'')],
    [('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b'')],
    [('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b'')],
    [('WScale', 15), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', b'')],
]

TS_SEQ_UNKNOWN = 0
TS_SEQ_ZERO = 1
TS_SEQ_2HZ = 2
TS_SEQ_100HZ = 3
TS_SEQ_1000HZ = 4
TS_SEQ_OTHER_NUM = 5
TS_SEQ_UNSUPPORTED = 6
IPID_SEQ_UNKNOWN = 0
IPID_SEQ_INCR = 1
IPID_SEQ_BROKEN_INCR = 2
IPID_SEQ_RPI = 3
IPID_SEQ_RD = 4
IPID_SEQ_CONSTANT = 5
IPID_SEQ_ZERO = 6
IPID_SEQ_INCR_BY_2 = 7


def Gcd(a, b):
    if 0 == b:
        return a;
    else:
        return Gcd(b, a % b);


def GcdN(digits):
    if 1 == len(digits):
        return digits[0];
    else:
        return Gcd(digits[0], GcdN(digits[1:]))


def reset_half_open(ip, ports):
    sr(IP(dst=ip) / TCP(dport=ports, flags='AR'), timeout=1)


port = 0


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def doTUITests():
    pass


def doSeqTests():
    pass


sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)


async def sendTSeqProbe(dhost, dport):
    ps = []
    for i in range(6):
        p = buildSendTn(dhost, dport, i)
        ps.append(p)
    for i in range(6):
        prbResMap[dhost]["si"]["sendtime"][i] = time.time()
        sock.sendto(ps[i][0], (ps[i][1], ps[i][2]))
        await asyncio.sleep(0.1)


def buildSendTn(dhost, dport, pn=0):
    p = IP(dst=dhost) / TCP(sport=tcpPortBase + pn, dport=dport, flags="S", seq=tcpSeqBase + pn, ack=tcpAck,
                            window=prbWindowSz[pn], options=prbOpts[pn])
    return (bytes(p), dhost, dport)


async def sendTIcmpProbe(dhost):
    p1 = IP(dst=dhost, tos=0, id=random.randint(1025, 60000), flags='DF') / ICMP(code=9, seq=295, id=icmpId) / (
            '\x00' * 120)
    sock.sendto(bytes(p1), (dhost, 0))

    p2 = IP(dst=dhost, tos=4, id=random.randint(1025, 60000), flags='DF') / ICMP(code=0, seq=296, id=icmpId + 1) / (
            '\x00' * 150)
    sock.sendto(bytes(p2), (dhost, 0))


async def sendTEcnProbe(dhost, dport):
    p = IP(dst=dhost) / TCP(sport=tcpPortBase + 12, dport=dport, flags=['S', 'C', 'E'], reserved=0b100, seq=tcpSeqBase,
                            ack=0,
                            window=prbWindowSz[6], options=prbOpts[6], urgptr=63477)
    sock.sendto(bytes(p), (dhost, dport))


async def sendTn(dhost, dport):
    # T1包含在seq中
    p2 = IP(dst=dhost, flags='DF') / TCP(sport=tcpPortBase + 14, dport=dport, flags=[], seq=tcpSeqBase, ack=tcpAck,
                                         window=prbWindowSz[7], options=prbOpts[7])
    sock.sendto(bytes(p2), (dhost, dport))

    p3 = IP(dst=dhost) / TCP(sport=tcpPortBase + 15, dport=dport, flags=['S', 'F', 'U', 'P'], seq=tcpSeqBase,
                             ack=tcpAck, window=prbWindowSz[8], options=prbOpts[8])
    sock.sendto(bytes(p3), (dhost, dport))

    p4 = IP(dst=dhost, flags='DF') / TCP(sport=tcpPortBase + 16, dport=dport, flags='A', seq=tcpSeqBase, ack=tcpAck,
                                         window=prbWindowSz[9], options=prbOpts[9])
    sock.sendto(bytes(p4), (dhost, dport))

    # 发送到关闭的端口
    p5 = IP(dst=dhost) / TCP(sport=tcpPortBase + 17, dport=1, flags='S', seq=tcpSeqBase, ack=tcpAck,
                             window=prbWindowSz[10], options=prbOpts[10])
    sock.sendto(bytes(p5), (dhost, 1))

    # 发送到关闭的端口
    p6 = IP(dst=dhost, flags='DF') / TCP(sport=tcpPortBase + 18, dport=1, flags='A', seq=tcpSeqBase, ack=tcpAck,
                                         window=prbWindowSz[11], options=prbOpts[11])
    sock.sendto(bytes(p6), (dhost, 1))

    # 发送到关闭的端口
    p7 = IP(dst=dhost) / TCP(sport=tcpPortBase + 19, dport=1, flags=['F', 'P', 'U'], seq=tcpSeqBase, ack=tcpAck,
                             window=prbWindowSz[12], options=prbOpts[12])
    sock.sendto(bytes(p7), (dhost, 1))


async def sendUDP(dhost):
    p = IP(dst=dhost, id=0x1042, ttl=udpTTL) / UDP(sport=udpPortBase, dport=1) / ('\x43' * 300)
    sock.sendto(bytes(p), (dhost, 1))


def ttlGuess(ttl):
    if ttl <= 32:
        return 32
    elif ttl <= 64:
        return 64
    elif ttl <= 128:
        return 128
    else:
        return 255


def getQ(p):
    res = []
    if p[TCP].reserved != 0:
        res.append('R')
    if 'U' not in p[TCP].flags and p[TCP].urgptr != 0:
        res.append('U')
    if len(res) <= 0:
        return None
    return ''.join(res)


def processTIcmpResp(p, testNo, resMap):
    if resMap["ii"]["received"][testNo] == 0:
        resMap["ii"]["received"][testNo] = 1
        resMap["ii"]["seqs"][testNo] = p[ICMP].seq
        resMap["ii"]["responses"] = resMap["ii"]["responses"] + 1
        resMap["ii"]["ipids"][testNo] = p.id
        if resMap["ii"]["received"][0] == 1 and resMap["ii"]["received"][1] == 1:
            resMap["ii"]["R"] = "Y"
            resMap["ii"]["T"] = p.ttl
            resMap["ii"]["TG"] = hex(ttlGuess(p.ttl))[2:]
        if 'DF' in p.flags:
            resMap["ii"]["DF"][testNo] = "Y"
        else:
            resMap["ii"]["DF"][testNo] = "N"


def processUdpResp(p, resMap):
    resMap["ui"]["R"] = "Y"
    if resMap["ui"]["responses"] == 0:
        resMap["ui"]["responses"] = 1
    if 'DF' in p.flags:
        resMap["ui"]["DF"] = "Y"
    else:
        resMap["ui"]["DF"] = "N"
    resMap["ui"]["T"] = p.ttl
    resMap["ui"]["TG"] = hex(ttlGuess(p.ttl))[2:]


def processICMP(p, resMap):
    if p[ICMP].type == 0:
        testNo = p[ICMP].id - icmpId
        if 0 <= testNo <= 1:
            processTIcmpResp(p, testNo, resMap)
    elif p[ICMP].type == 3 and p[ICMP].code == 3:
        processUdpResp(p, resMap)


def getOptTs(options):
    if options is None:
        return -1
    for option in options:
        if option[0] == 'Timestamp':
            return option[1]
    return -1


def parseOptStr(options):
    if options is None:
        return None
    res = ''
    for option in options:
        if option[0] == 'EOL':
            res += 'L'
        elif option[0] == 'NOP':
            res += 'N'
        elif option[0] == 'MSS':
            res += 'M'
            res += hex(option[1])[2:].upper()
        elif option[0] == 'WScale':
            res += 'W'
            res += hex(option[1])[2:].upper()
        elif option[0] == 'SAckOK':
            res += 'S'
        elif option[0] == 'Timestamp':
            res += 'T'
            if option[1][0] is not None and option[1][0] > 0:
                res += '1'
            else:
                res += '0'
            if option[1][1] is not None and option[1][1] > 0:
                res += '1'
            else:
                res += '0'
    return res


def processT1_7Resp(p, relayNo, resMap):
    if resMap["ti"]["received"][relayNo] == 0:
        resMap["ti"]["R"][relayNo] = "Y"
        resMap["ti"]["received"][relayNo] = 1
        resMap["ti"]["seqs"][relayNo] = p[TCP].seq
        resMap["ti"]["responses"] = resMap["ti"]["responses"] + 1
        resMap["ti"]["ipids"][relayNo] = p.id
        resMap["ti"]["T"][relayNo] = p.ttl
        resMap["ti"]["TG"][relayNo] = hex(ttlGuess(p.ttl))[2:]
        resMap["ti"]["Q"][relayNo] = getQ(p)
        if 'DF' in p.flags:
            resMap["ti"]["DF"][relayNo] = "Y"
        else:
            resMap["ti"]["DF"][relayNo] = "N"

        if p[TCP].seq == 0:
            resMap["ti"]["S"][relayNo] = "Z"
        elif p[TCP].seq == tcpAck:
            resMap["ti"]["S"][relayNo] = "A"
        elif p[TCP].seq == tcpAck+1:
            resMap["ti"]["S"][relayNo] = "A+"
        else:
            resMap["ti"]["S"][relayNo] = "O"


def processTEcnResp(p, resMap):
    resMap["ei"]["R"] = "Y"
    if resMap["ei"]["responses"] == 0:
        resMap["ei"]["responses"] = resMap["ei"]["responses"] + 1
        resMap["ei"]["T"] = p.ttl
        resMap["ei"]["TG"] = hex(ttlGuess(p.ttl))[2:]
        resMap["ei"]["Q"] = getQ(p)
        if 'DF' in p.flags:
            resMap["ei"]["DF"] = "Y"
        else:
            resMap["ei"]["DF"] = "N"
        if 'E' in p[TCP].flags and 'C' in p[TCP].flags:
            resMap["ei"]["CC"] = "S"
        elif 'E' in p[TCP].flags:
            resMap["ei"]["CC"] = "Y"
        elif 'C' not in p[TCP].flags:
            resMap["ei"]["CC"] = "N"
        else:
            resMap["ei"]["CC"] = "O"


def processTCP(p, resMap):
    dport = p.dport
    testNo = dport - tcpPortBase
    if testNo >= 0 and testNo < 6:
        processTSeqResp(p, testNo, resMap)
        if testNo == 0:
            processT1_7Resp(p, 0, resMap)
    elif testNo == 12:
        processTEcnResp(p, resMap)
    elif testNo >= 14 and testNo <= 19:
        processT1_7Resp(p, testNo - 14 + 1, resMap)


def processUDP(p, resMap):
    print('udp')
    pass


def processTSeqResp(p, testNo, resMap):
    if p[TCP].flags.R and resMap["si"]["responses"] == 0:
        # TODO 收到拒绝包,重新发送
        return False
    if not p[TCP].flags.S or not p[TCP].flags.A:
        print('接收错误')
        return False
    ack = p[TCP].ack
    seq_response_num = ack - tcpSeqBase - 1
    if seq_response_num != testNo:
        print('seq_response_num != testNo')
        return False
    if resMap["si"]["received"][testNo] == 0:
        resMap["si"]["received"][testNo] = 1
        resMap["si"]["seqs"][testNo] = p[TCP].seq
        resMap["si"]["win"][testNo] = p[TCP].window
        resMap["si"]["responses"] = resMap["si"]["responses"] + 1
        resMap["si"]["ipids"][testNo] = p.id
        resMap["si"]["option_str"][testNo] = parseOptStr(p[TCP].options)
        optTs = getOptTs(p[TCP].options)
        if optTs == -1:
            resMap["si"]['ts_seqclass'] = TS_SEQ_UNSUPPORTED
        elif optTs == 0:
            resMap["si"]['ts_seqclass'] = TS_SEQ_ZERO
        else:
            resMap["si"]["timestamps"][testNo] = optTs
        return True
    return False


def filter(x):
    sip = x[IP].src
    if sip not in prbResMap:
        return
    if x[IP].proto == 1:
        processICMP(x[IP], prbResMap[sip])
    elif x[IP].proto == 6:
        processTCP(x[IP], prbResMap[sip])
    elif x[IP].proto == 17:
        processUDP(x[IP], prbResMap[sip])


def capIp():
    sniff(iface="enx0023545c9a76", filter="ip", count=0, prn=lambda x: filter(x))


def initResMap():
    return {
        "R": "N",
        "si": {  # seq
            "responses": 0,
            "sendtime": [0, 0, 0, 0, 0, 0],
            "received": [0, 0, 0, 0, 0, 0],
            "seqs": [0, 0, 0, 0, 0, 0],
            "ipids": [0, 0, 0, 0, 0, 0],
            "ts_seqclass": 0,
            "timestamps": [0, 0, 0, 0, 0, 0],
            "option_str": [None, None, None, None, None, None],
            "win": [0, 0, 0, 0, 0, 0]
        },
        "ii": {  # icmp
            "T": None,
            "TG": None,
            "R": "N",
            "DF": [None, None],
            "responses": 0,
            "received": [0, 0],
            "seqs": [0, 0],
            "ipids": [0, 0],
        },
        "ti": {  # time
            "T": [None, None, None, None, None, None, None],
            "TG": [None, None, None, None, None, None, None],
            "R": ["N", "N", "N", "N", "N", "N", "N"],
            "DF": [None, None, None, None, None, None, None],
            "Q": [None, None, None, None, None, None, None],
            "S": [None, None, None, None, None, None, None],
            "A": [None, None, None, None, None, None, None],
            "responses": 0,
            "received": [0, 0, 0, 0, 0, 0, 0],
            "seqs": [0, 0, 0, 0, 0, 0, 0],
            "ipids": [0, 0, 0, 0, 0, 0, 0],
        },
        "ui": {  # udp
            "T": None,
            "TG": None,
            "R": "N",
            "responses": 0,
            "DF": None
        },
        "ei": {  # en
            "T": None,
            "TG": None,
            "CC": None,
            "R": "N",
            "responses": 0,
            "DF": None,
            "Q": None,
        },
    }


# 识别TI, CI, II
def getXI(ipids):
    zero = True
    for i in range(len(ipids)):
        ipid = ipids[i]
        if ipid != 0:
            zero = False
            break
    if zero:
        return 'Z'

    diffs = []
    for i in range(len(ipids) - 1):
        if ipids[i + 1] > ipids[i]:
            diffs.append(ipids[i + 1] - ipids[i])
        else:
            diffs.append(ipids[i + 1] - ipids[i] + 0xFFFF + 1)

    if len(diffs) > 1:
        eq2w = True
        for i in range(len(diffs)):
            diff = diffs[i]
            if diff < 20000:
                eq2w = False
                break
        if eq2w:
            return 'RD'

    alleq = True
    for i in range(len(diffs)):
        diff = diffs[i]
        if diff != 0:
            alleq = False
            break
    if alleq:
        return hex(ipids[0])[2:].upper()

    for i in range(len(diffs)):
        if diffs[i] > 1000 and diffs[i] % 256 != 0 or diffs[i] % 256 == 0 and diffs[i] >= 25600:
            return 'RI'

    BI = True
    for i in range(len(diffs)):
        diff = diffs[i]
        if diff % 256 != 0 or diff > 5120:
            BI = False
            break
    if BI:
        return 'BI'

    I = True
    for i in range(len(diffs)):
        diff = diffs[i]
        if diff > 9:
            I = False
            break
    if I:
        return 'I'

    return None


def getIpIds(received, ipids):
    relIpIds = []
    for i in range(len(received)):
        if received[i] == 1:
            relIpIds.append(ipids[i])
    return relIpIds


def avgIpidInc(ipids):
    diffs = []
    diffSum = 0.
    for i in range(len(ipids)):
        if ipids[i] < ipids[i + 1]:
            diffs.append(ipids[i + 1] - ipids[i])
        else:
            diffs.append(ipids[i + 1] - ipids[i] + 0xFFFF)
    for i in range(len(diffs)):
        diffSum += diffs[i]
    return diffSum / len(diffs)


def computeParams(resMap):
    # GCD
    seqTseq = resMap["si"]["seqs"]
    diffs = []
    for i in range(5):
        if seqTseq[i] < seqTseq[i + 1]:
            diffs.append(seqTseq[i + 1] - seqTseq[i])
        else:
            diffs.append(seqTseq[i + 1] - seqTseq[i] + 0xFFFFFFFF)
    GCD = GcdN(diffs)

    sendtimes = resMap["si"]["sendtime"]
    timediffs = []
    for i in range(5):
        timediffs.append(sendtimes[i + 1] - sendtimes[i])
    seq_rates = []
    for i in range(5):
        seq_rates.append(diffs[i] * 1. / timediffs[i])
    seq_avg_rate = sum(seq_rates) / 5.
    seq_rate = 0
    siindex = 0
    seq_stddev = 0
    if GCD > 0:
        seq_rate = math.log(seq_avg_rate) / math.log(2.)
        seq_rate = int(seq_rate * 8 + 0.5)
        div_gcd = 1.
        if GCD > 9:
            div_gcd = GCD

        for i in range(5):
            rtmp = seq_rates[i] / div_gcd - seq_avg_rate / div_gcd
            seq_stddev += rtmp * rtmp
        seq_stddev /= 4
        seq_stddev = math.sqrt(seq_stddev)

        if seq_stddev > 1:
            seq_stddev = math.log(seq_stddev) / math.log(2.0)
            siindex = int(seq_stddev * 8 + 0.5)
    ISR = seq_rate
    SP = siindex
    TI = getXI(resMap["si"]["ipids"])
    print(hex(ISR))
    print(hex(SP))
    print(TI)
    II = None
    DFI = None
    if resMap["ii"]["received"][0] == 1 and resMap["ii"]["received"][1] == 1:
        II = getXI(resMap["ii"]["ipids"])
        print('II=%s' % II)
        if resMap["ii"]["DF"][0] == 'Y' and resMap["ii"]["DF"][1] == 'Y':
            DFI = "Y"
        elif resMap["ii"]["DF"][0] == 'Y' and resMap["ii"]["DF"][1] == 'N':
            DFI = "S"
        elif resMap["ii"]["DF"][0] == 'N' and resMap["ii"]["DF"][1] == 'N':
            DFI = "N"
        else:
            DFI = "O"

    closeIpIds = getIpIds(resMap["ti"]["received"][4:], resMap["ti"]["ipids"][4:])
    if len(closeIpIds) >= 2:
        CI = getXI(closeIpIds)
        print('CI=%s' % CI)

    if II == 'RI' or II == 'BI' or II == 'I' and TI == 'RI' or TI == 'BI' or TI == 'I':
        if resMap["si"]["ipids"][5] + 3 * avgIpidInc(resMap["si"]["ipids"]) > resMap["ii"]["ipids"][0]:
            SS = 'S'
        else:
            SS = 'O'
        print(SS)

    if resMap["si"]['ts_seqclass'] == TS_SEQ_UNSUPPORTED:
        TS = 'U'
    elif resMap["si"]['ts_seqclass'] == TS_SEQ_ZERO:
        TS = 0
    else:
        avg_ts_hz = 0.
        for i in range(5):
            ts_diff = resMap["si"]['timestamps'][i + 1][1] - resMap["si"]['timestamps'][i][1]
            ts_sec_diff = resMap["si"]['sendtime'][i + 1] - resMap["si"]['sendtime'][i]
            dhz = ts_diff / ts_sec_diff
            avg_ts_hz += dhz / 5
        if 0 < avg_ts_hz < 5.66:
            resMap["si"]['ts_seqclass'] = TS_SEQ_2HZ
        elif 70 < avg_ts_hz < 150:
            resMap["si"]['ts_seqclass'] = TS_SEQ_100HZ
        elif 724 < avg_ts_hz < 1448:
            resMap["si"]['ts_seqclass'] = TS_SEQ_1000HZ
        elif avg_ts_hz > 0:
            resMap["si"]['ts_seqclass'] = TS_SEQ_OTHER_NUM

        if resMap["si"]['ts_seqclass'] in [TS_SEQ_2HZ, TS_SEQ_100HZ, TS_SEQ_1000HZ, TS_SEQ_OTHER_NUM]:
            if avg_ts_hz <= 5.66:
                TS = 1
            elif 70 < avg_ts_hz <= 150:
                TS = 7
            elif 150 < avg_ts_hz <= 350:
                TS = 8
            else:
                TS = int(0.5 + math.log(avg_ts_hz) / math.log(2.0))
        TS = str(TS)
        print("TS=%s" % TS)

    O1 = str(resMap["si"]["option_str"][0])
    O2 = str(resMap["si"]["option_str"][1])
    O3 = str(resMap["si"]["option_str"][2])
    O4 = str(resMap["si"]["option_str"][3])
    O5 = str(resMap["si"]["option_str"][4])
    O6 = str(resMap["si"]["option_str"][5])

    W1 = hex(resMap["si"]["win"][0])[2:].upper()
    W2 = hex(resMap["si"]["win"][1])[2:].upper()
    W3 = hex(resMap["si"]["win"][2])[2:].upper()
    W4 = hex(resMap["si"]["win"][3])[2:].upper()
    W5 = hex(resMap["si"]["win"][4])[2:].upper()
    W6 = hex(resMap["si"]["win"][5])[2:].upper()

    print("W1=%s" % W1)
    print("W2=%s" % W2)
    print("W3=%s" % W3)
    print("W4=%s" % W4)
    print("W5=%s" % W5)
    print("W6=%s" % W6)

    R = resMap["R"]
    print(resMap)


async def sendProbe(dhost, dport):
    await sendTSeqProbe(dhost, dport)
    await sendTIcmpProbe(dhost)
    await sendTEcnProbe(dhost, dport)
    await sendTn(dhost, dport)
    await sendUDP(dhost)
    await asyncio.sleep(3)
    computeParams(prbResMap[dhost])


if __name__ == '__main__':
    conf.verb = 0  
    start_time = time.time()
    tcpSeqBase = random.randint(1000, 200000000)
    tcpAck = random.randint(1000, 200000000)
    tcpPortBase = random.randint(1025, 60000)
    udpPortBase = random.randint(1025, 60000)
    icmpId = random.randint(1025, 60000)
    udpTTL = int(time.time()) % 14 + 51
    prbResMap = {} 
    for ip in []:
        prbResMap[ip] = initResMap()
    t1 = threading.Thread(target=capIp, args=())
    t1.setDaemon(False)
    t1.start()
    time.sleep(1)
    loop = asyncio.get_event_loop()
    tasks=[]
    for ip in []:
        tasks.append(sendProbe(ip, 80))
    loop.run_until_complete(asyncio.wait(tasks))
