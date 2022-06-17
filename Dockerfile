FROM alpine:latest
RUN wget https://github.com/shadow1ng/fscan/releases/download/1.7.1/fscan_amd64
RUN mv fscan_amd64 fscan && chmod +x fscan