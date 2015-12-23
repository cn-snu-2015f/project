# Computer Network 2015f Project
- Member: 김준호, 선동성, 장원재


# Kernel Space
- Working directory: build_dir/target-mips_34kc_uClibc-0.9.33.2/linux-ar71xx_generic/compat-wireless-2014-05-22/drivers/net/wireless/ath/ath9k/
- Modified file: xmit.c

# User Space
- C file: recorder.c
- Compile: gcc -w -o recorder recorder.c -lpcap -lnetfilter_queue -lnfnetlink
 - preset:<br>
  - sudo iptables -F<br>
  - sudo iptables -A OUTPUT -p tcp -j NFQUEUE<br>
  - sudo iptables -A INPUT -p tcp -j NFQUEUE<br>
- Cross Compile: mips-openwrt-linux-gcc -w -o recorder recorder.c -I$BUILDROOT/include -L$BUILDROOT/lib -o test -lnfnetlink -lnetfilter_queue -lmnl
 - $BUILDROOT = openwrt/staging_dir/target-mips_34kc_uClibc-0.9.33.2/usr/
 - libnetfilter-queue 폴더를 openwrt/package/lib에 넣는다.
 - make menuconfig의 Libraries - libnetlink, libpcap, libnetfilter-queue, libmnl을 *로 선택한다.
 - opkg install libnetfilter-queue 등으로 실행에 필요한 library를 openwrt에 설치한다

# 구현 목표
- Kernel Space에서 L2 ACK이 도착한 TCP 패킷을 찾는다. 
 - 완료
- User Space에서 들어온 TCP 패킷의 ACK을 제작한다. 
 - 반 완료
- Kernel Space에서 얻은 정보를 User Space로 전달한다 
 - 미구현
- 원래 생성되는 TCP ACK을 Drop한다. 
 - 완료

# 테스트 방법
- recorder.c
 - 준비물 : server computer, client computer
 - server computer에서 서버를 연다. (ex : Berryz WebShare - http 파일 서버)
 - client computer에 recorder.c를 설치하고 preset과 컴파일을 한다.
 - client computer에서 sudo ./recorder로 recorder를 실행시킨다.
 - client computer에서 server computer의 서버로 접속을 시도한다.
 - server computer에서 wireshark로 client computer에서 오는 packet을 캡쳐하여 fake ACK를 확인한다.
