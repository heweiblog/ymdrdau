
ifeq ($(origin PYENV_ROOT), undefined)
$(error `pyenv` is required for the Target.)
endif

PYVER := $(lastword $(shell python --version 2>&1))
APPVER := $(strip $(shell cat version))
GITBRANCH := $(strip $(shell git rev-parse --abbrev-ref HEAD))
GITCOMMIT := $(strip $(shell git rev-parse --short HEAD))

all: build

rpm: build
	mkdir -p ymdrdau-$(APPVER)/bin ymdrdau-$(APPVER)/etc ymdrdau-$(APPVER)/etc/init.d
	cp dist/ymdrdau ymdrdau-$(APPVER)/bin
	cp ymdrdau.py ymdrdau-$(APPVER)
	cp -r etc ymdrdau-$(APPVER)
	cp build/pyinst-ymdrdau/base_library.zip ymdrdau-$(APPVER)/etc
	tar cvzf ~/rpmbuild/SOURCES/ymdrdau-$(APPVER).tar.gz ymdrdau-$(APPVER)
	rpmbuild -bb --define "DRMSVER $(APPVER)" --define "GITBRANCH $(GITBRANCH)" --define "GITCOMMIT $(GITCOMMIT)" ymdrdau.spec
	rm -rf ymdrdau-$(APPVER)

TGT=ymdrdau
rpmclean:	
	rm -rf build dist
	rm -rf ymdrdau-$(APPVER)
	rm -rf __pycache__
	cp -r ~/rpmbuild/RPMS/x86_64/$(TGT)*$(APPVER)* ./  
	rm -rf ~/rpmbuild/SOURCES/$(TGT)* \
	~/rpmbuild/BUILD/$(TGT)* \
	~/rpmbuild/RPMS/x86_64/$(TGT)* \
	~/rpmbuild/SPEC/$(TGT)* 

build: dist/ymdrdau

dist/ymdrdau: distclean
	env LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):$(PYENV_ROOT)/versions/$(PYVER)/lib/ pyinstaller --onefile pyinst-ymdrdau.spec

.PHONY: distclean clean

distclean:
	rm -rf build dist
	rm -rf ymdrdau-$(APPVER)
	rm -rf __pycache__

clean:
	rm -rf build dist
	rm -rf ymdrdau-$(APPVER)
	rm -rf __pycache__
