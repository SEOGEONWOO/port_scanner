# 사용자에게 여러 IP 입력받기
target_input = input("IP를 입력하시오 (여러 개의 IP는 ','로 구분): ")

# 입력받은 문자열을 ','로 구분하여 리스트로 변환
target_ips = target_input.split(',')

# 리스트의 각 IP를 출력해보기
for target in target_ips:
    print(f"Scanning target IP: {target.strip()}")
