all: build

build:
	cargo build --release

install:
	cp target/release/wirespider /usr/local/bin
	if ! [ -e /etc/wirespider/wg0 ]; then \
		cp systemd/wirespider/wg0 /etc/wirespider/wg0; \
	else \
		cp -f systemd/wirespider/wg0 /etc/wirespider/wg0.new; \
	fi
	cp target/release/wirespider /usr/local/bin
	mkdir -p /etc/wirespider/keys
	cp systemd/system/wirespider-client@.service /etc/systemd/system

clean:
	rm /usr/local/bin/wirespider
	rm -r /etc/wirespider/keys
	rm -r /etc/wirespider
	rm /etc/wirespider/wg0
	rm /etc/systemd/system/wirespider-client@.service


