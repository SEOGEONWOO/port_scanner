from scapy.all import *
import time

def xmas_scan(target, portRange):
    print(f"Scanning target: {target} on ports: {portRange}")
    for port in portRange:
        # X-mas 패킷 생성 (FIN, PSH, URG 플래그 설정)
        xmas_packet = IP(dst=target)/TCP(dport=port, flags="FPU")
        # 패킷 전송 및 응답 수신
        response = sr1(xmas_packet, timeout=0.5, verbose=0)

        # 응답 분석
        if response is None:  # 응답 없음 = 포트 열림 또는 필터링됨
            print(f"Port {port} is open or filtered!")
        elif response.haslayer(TCP) and response[TCP].flags == "R":  # RST = 포트 닫힘
            print(f"Port {port} is closed.")
        else:  # 그 외 응답
            print(f"Port {port} is filtered or no response.")

start_time = time.time()
# 스캔 대상 및 포트 범위
targetIP = "54.180.158.188"
portsToScan = range(20, 25)

xmas_scan(targetIP, portsToScan)

end_time = time.time()

print(f"Execution time: {end_time - start_time:.6f} seconds")
