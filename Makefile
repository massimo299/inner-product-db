
CXXFLAGS=-g
CXXFLAGS= -std=gnu++11 -D_REENTRANT
BNOBJB=  bn_pair.o  zzn2.o zzn12a.o       zzn4.o ecn2.o big.o zzn.o ecn.o base64.o oe-m.o aoe-m.o

EXE= aoe-m-driver aoen-m-driver GenKey EncRow GenToken ApplyToken ApplyPToken ApplyMToken

EXE: ${EXE}

aoe-m-driver.o: aoe-m-driver.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c aoe-m-driver.cpp -o aoe-m-driver.o

aoen-m-driver.o: aoen-m-driver.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c aoen-m-driver.cpp -o aoen-m-driver.o

GenKey.o: GenKey.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c GenKey.cpp -o GenKey.o

EncRow.o: EncRow.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c EncRow.cpp -o EncRow.o

GenToken.o: GenToken.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c GenToken.cpp -o GenToken.o

ApplyToken.o: ApplyToken.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ApplyToken.cpp -o ApplyToken.o

ApplyPToken.o: ApplyPToken.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ApplyPToken.cpp -o ApplyPToken.o

ApplyMToken.o: ApplyMToken.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ApplyMToken.cpp -o ApplyMToken.o

aoe-m-driver: ${BNOBJB} aoe-m-driver.o
	g++ -o aoe-m-driver ${BNOBJB} aoe-m-driver.o miracl.a -lcrypto -lssl -lpthread -g

aoen-m-driver: ${BNOBJB} aoen-m-driver.o
	g++ -o aoen-m-driver ${BNOBJB} aoen-m-driver.o miracl.a -lcrypto -lssl -lpthread -g

GenKey: ${BNOBJB} GenKey.o
	g++ -o GenKey ${BNOBJB} GenKey.o miracl.a -lcrypto -lssl -lpthread -g

EncRow: ${BNOBJB} EncRow.o
	g++ -o EncRow ${BNOBJB} EncRow.o miracl.a -lcrypto -lssl -lpthread -g

GenToken: ${BNOBJB} GenToken.o
	g++ -o GenToken ${BNOBJB} GenToken.o miracl.a -lcrypto -lssl -lpthread -g

ApplyToken: ${BNOBJB} ApplyToken.o
	g++ -o ApplyToken ${BNOBJB} ApplyToken.o miracl.a -lcrypto -lssl -lpthread -g

ApplyPToken: ${BNOBJB} ApplyPToken.o
	g++ -o ApplyPToken ${BNOBJB} ApplyPToken.o miracl.a -lcrypto -lssl -lpthread -g

ApplyMToken: ${BNOBJB} ApplyMToken.o
	g++ -o ApplyMToken ${BNOBJB} ApplyMToken.o miracl.a -lcrypto -lssl -lpthread -g

oe-m.o: oe-m.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c oe-m.cpp -o oe-m.o -g

aoe-m.o: aoe-m.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c aoe-m.cpp -o aoe-m.o -g

all: ${EXE}

clean:
	rm -f ${BNOBJB} ${EXE} GenKey.o EncRow.o GenToken.o ApplyToken.o ApplyPToken.o ApplyMToken.o
