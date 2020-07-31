# Docker build image for the Homeland of Things Framework IoT Analysis
# https://homelandofthings.org @reaperb0t (Daniel West)
# http://blog.obscuritylabs.com/
# http://cybersyndicates.org

FROM kalilinux/kali

WORKDIR /root/

# Referenced: https://hub.docker.com/r/v00d00sec/kali-mini
# Referenced: https://github.com/v00d00sec/kali-minimal-dockerfile
# Referenced: https://github.com/attify/firmware-analysis-toolkit

RUN set -eux; apt-get update; \
	apt-get -y install apt-transport-https; \
	apt-get -y install \
		apt bc gettext-base man-db fontconfig powerline \
		nmap hydra john tcpdump metasploit-framework \
		sqlmap fierce dnsrecon dirb python-pip git \
		nginx sslscan dnsenum dnsmap p0f joomscan \
		davtest wfuzz sipvicious gpp-decrypt \
		patator wordlists enum4linux onesixtyone apktool \
		dex2jar smali ridenum webshells snmpcheck \
		dnsutils rsh-client gdb git exploitdb vim gnuradio \
		gqrx-sdr hackrf tree locate default-jre busybox-static \
		fakeroot kpartx netcat-openbsd \
		python3-psycopg2 snmp uml-utilities util-linux vlan \
		qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils \
		build-essential zlib1g-dev liblzma-dev \
		python-gtk2 python-cairo python-usb python-crypto \
		python-serial python-dev libgcrypt-dev python-pip \
		python-scapy gdb-multiarch x11vnc xvfb iceweasel \
		# Todo: Replace
		#sslstrip jad python-psycopg2 python-magic \
		mitmproxy binwalk ltrace strace; \
	mkdir /tmp/docker_tmp; \
	updatedb; \
	#
	# git clone additional tools
	git clone --depth=1 --recursive https://github.com/attify/firmware-analysis-toolkit ./firmware-analysis-toolkit/; \
      rm -rf ./firmware-analysis-toolkit/firmadyne; \
      rm -rf ./firmware-analysis-toolkit/firmwalker; \
      rm -rf ./firmware-analysis-toolkit/firmware-mod-kit; \
    git clone --depth=1 --recursive https://github.com/zcutlip/nvram-faker.git ./firmware-analysis-toolkit/nvram-faker; \
    git clone --depth=1 --recursive https://github.com/firmadyne/firmadyne ./firmware-analysis-toolkit/firmadyne; \
    git clone --depth=1 --recursive https://github.com/craigz28/firmwalker ./firmware-analysis-toolkit/firmwalker; \
    git clone --depth=1 --recursive https://github.com/mirror/firmware-mod-kit ./firmware-analysis-toolkit/firmware-mod-kit; \
    git clone --depth=1 --recursive https://github.com/JonathanSalwan/ROPgadget.git ./firmware-analysis-toolkit/ROPgadget; \
    git clone --depth=1 --recursive https://github.com/hugsy/gef ./firmware-analysis-toolkit/gef; \
    git clone --depth=1 --recursive https://github.com/longld/peda.git ./firmware-analysis-toolkit/peda; \
    git clone --depth=1 --recursive https://github.com/719Ben/baudrate.py ./firmware-analysis-toolkit/baudrate/; \
    git clone --depth=1 --recursive https://github.com/andresriancho/w3af.git ./w3af; \
    git clone --depth=1 --recursive https://github.com/x893/BusPirateConsole ./BusPirateConsole; \
    git clone --depth=1 --recursive https://github.com/cyphunk/JTAGenum ./JTAGenum; \
    git clone --depth=1 --recursive https://github.com/attify/attify-badge ./attify-badge; \
    git clone --depth=1 --recursive https://github.com/attify/Attify-Zigbee-Framework ./Attify-Zigbee-Framework; \
    git clone --depth=1 --recursive https://github.com/pwnieexpress/blue_hydra ./blue_hydra; \
    git clone --depth=1 --recursive https://github.com/buildroot/buildroot ./buildroot; \
    git clone --depth=1 --recursive https://github.com/KJCracks/Clutch ./Clutch; \
    git clone --depth=1 --recursive https://github.com/jeremylong/DependencyCheck ./DependencyCheck; \
    git clone --depth=1 --recursive https://github.com/stefanesser/dumpdecrypted ./dumpdecrypted; \
    git clone --depth=1 --recursive https://github.com/praetorian-inc/DVRF ./DVRF; \
    git clone --depth=1 --recursive https://github.com/google/enjarify ./enjarify; \
    git clone --depth=1 --recursive https://github.com/cureHsu/EZ-Wave ./EZ-Wave; \
    git clone --depth=1 --recursive https://github.com/ptrkrysik/gr-gsm ./gr-gsm; \
    git clone --depth=1 --recursive https://github.com/skylot/jadx ./jadx; \
    git clone --depth=1 --recursive https://github.com/java-decompiler/jd-gui ./jd-gui; \
    git clone --depth=1 --recursive https://github.com/sviehb/jefferson ./jefferson; \
    git clone --depth=1 --recursive https://github.com/grandideastudio/jtagulator ./jtagulator; \
    git clone --depth=1 --recursive https://github.com/ttsou/kalibrate ./kalibrate; \
    git clone --depth=1 --recursive https://github.com/steve-m/kalibrate-rtl ./kalibrate-rtl; \
    git clone --depth=1 --recursive https://github.com/scateu/kalibrate-hackrf ./kalibrate-hackrf; \
    git clone --depth=1 --recursive https://github.com/Nuand/kalibrate-bladeRF ./kalibrate-bladeRF; \
    git clone --depth=1 --recursive https://github.com/riverloopsec/killerbee ./killerbee; \
    git clone --depth=1 --recursive https://github.com/greatscottgadgets/libbtbb ./libbtbb; \
    git clone --depth=1 --recursive https://github.com/devttys0/libmpsse ./libmpsse; \
    git clone --depth=1 --recursive https://github.com/DanBeard/LibScanner ./LibScanner; \
    git clone --depth=1 --recursive https://github.com/CISOfy/lynis ./lynis; \
    git clone --depth=1 --recursive https://github.com/MobSF/Mobile-Security-Framework-MobSF ./Mobile-Security-Framework-MobSF; \
    git clone --depth=1 --recursive https://github.com/blasty/moneyshot ./moneyshot; \
    git clone --depth=1 --recursive https://github.com/nodesecurity/nsp ./nsp; \
    git clone --depth=1 --recursive https://github.com/gnu-mcu-eclipse/openocd ./openocd; \
    git clone --depth=1 --recursive https://github.com/radare/radare2 ./radare2; \
    git clone --depth=1 --recursive https://github.com/RetireJS/retire.js ./retire.js; \
    git clone --depth=1 --recursive https://github.com/sqlcipher/sqlcipher ./sqlcipher; \
    git clone --depth=1 --recursive https://github.com/theupdateframework/tuf ./tuf; \
    git clone --depth=1 --recursive https://github.com/greatscottgadgets/ubertooth ./ubertooth; \
    git clone --depth=1 --recursive https://github.com/uptane/uptane ./uptane; \
    git clone --depth=1 --recursive https://github.com/jopohl/urh ./urh; \
    git clone --depth=1 --recursive https://github.com/osqzss/gps-sdr-sim ./gps-sdr-sim; \
    git clone --depth=1 --recursive https://github.com/Oros42/IMSI-catcher ./IMSI-catcher; \
    git clone --depth=1 --recursive https://github.com/cn0xroot/RFSec-ToolKit ./RFSec-ToolKit; \
    git clone --depth=1 --recursive https://github.com/xmikos/qspectrumanalyzer ./qspectrumanalyzer; \
    git clone --depth=1 --recursive https://github.com/hathcox/py-hackrf ./py-hackrf; \
    git clone --depth=1 --recursive https://github.com/realraum/hackrf-dvb-t ./hackrf-dvb-t; \
    git clone --depth=1 --recursive https://github.com/f4exb/sdrangel ./sdrangel; \
    git clone --depth=1 --recursive https://github.com/h3xstream/burp-retire-js ./burp-retire-js; \
    git clone --depth=1 --recursive https://github.com/mirrorer/afl ./afl; \
    git clone --depth=1 --recursive https://github.com/rmadair/fuzzer ./rmadair; \
    git clone --depth=1 --recursive https://github.com/samhocevar/zzuf ./zzuf; \
    git clone --depth=1 --recursive https://github.com/aoh/radamsa ./radamsa; \
    git clone --depth=1 --recursive https://github.com/binspector/binspector ./binspector; \
    git clone --depth=1 --recursive https://github.com/renatahodovan/grammarinator ./grammarinator; \
    git clone --depth=1 --recursive https://github.com/jtpereyda/boofuzz ./boofuzz; \
    #
	# install and configure additional tools
	./firmware-analysis-toolkit/binwalk/deps.sh --yes; \
	#BROKE: python ./firmware-analysis-toolkit/binwalk/setup.py install; \
	pip install capstone unicorn keystone-engine pexpect; \
	chmod +x ./firmware-analysis-toolkit/fat.py; \
	chmod +x ./firmware-analysis-toolkit/reset.py; \
	sed -i -e 's/\/home\/vagrant\/firmadyne\//\/root\/firmware-analysis-toolkit\/firmadyne\//g' ./firmware-analysis-toolkit/firmadyne/firmadyne.config; \
	echo "root:root" | chgpasswd; \
	sed -i -e 's/\/home\/ec\/firmadyne/\/root\/firmware-analysis-toolkit\/firmadyne/g' ./firmware-analysis-toolkit/fat.py; \
	sed -i -e 's/\.\/src\/binwalk\/src\/scripts\/binwalk/\/usr\/local\/bin\/binwalk/g' ./firmware-analysis-toolkit/firmware-mod-kit/shared-ng.inc

#
# ports to be exposed
EXPOSE 53
EXPOSE 80
EXPOSE 443
EXPOSE 5900
EXPOSE 8000
EXPOSE 8080
EXPOSE 8443
