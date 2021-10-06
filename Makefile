ifeq ($(PREFIX),)
PREFIX := "/opt/openresty"
endif

all:

install:
	for f in ./lualib/resty/*.lua; do \
		install -D -t $(PREFIX)/lualib/resty $$f; \
	done
