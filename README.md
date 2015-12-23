# Computer Network 2015f Project
- Member: 김준호, 선동성, 장원재


# Kernel Space
- Working directory: build_dir/target-mips_34kc_uClibc-0.9.33.2/linux-ar71xx_generic/compat-wireless-2014-05-22/drivers/net/wireless/ath/ath9k/
- Modified file: xmit.c

# User Space
- C file: recorder.c
- Compile: gcc -w -o recorder recorder.c -lpcap -lnetfilter_queue -lnfnetlink
- Cross Compile: mips-openwrt-linux-gcc -w -o recorder recorder.c -I$BUILDROOT/include -L$BUILDROOT/lib -o test -lnfnetlink -lnetfilter_queue -lmnl
 - $BUILDROOT = openwrt/staging_dir/target-mips_34kc_uClibc-0.9.33.2/usr/
# 구현 목표
- Kernel Space에서 L2 ACK이 도착한 TCP 패킷을 찾는다. 
 - 완료
- User Space에서 들어온 TCP 패킷의 ACK을 제작한다. 
 - 반 완료
- Kernel Space에서 얻은 정보를 User Space로 전달한다 
 - 미구현
- 원래 생성되는 TCP ACK을 Drop한다. 
 - 완료
