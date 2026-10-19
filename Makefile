BINARY := cookie-dump
DIST := dist

.PHONY: build clean

build:
	go build -trimpath -ldflags="-s -w" -o $(DIST)/$(BINARY) .

clean:
	rm -rf $(DIST)
