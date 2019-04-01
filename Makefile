OTPTOOLVER = 1.0

.PHONY: clean

LDLIBS += -lgcrypt

otptool: ec.o otptool.o

all: otptool

clean:
	rm -f otptool otptool.exe *.o

README.md: otptool.1
	mandoc -Tmarkdown otptool.1 > README.md
	sed -i '1,2d;$$d;s/&nbsp;/ /g' README.md

dist:
	mkdir otptool-$(OTPTOOLVER)
	cp Makefile *.c *.h *.1 *.md otptool-$(OTPTOOLVER)
	tar czf otptool-$(OTPTOOLVER).tar.gz --owner=root --group=root --format=ustar otptool-$(OTPTOOLVER)
	rm -rf otptool-$(OTPTOOLVER)

