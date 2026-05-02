FROM alpine:3.22

RUN apk add --no-cache lua5.4 \
    && ln -s /usr/bin/lua5.4 /usr/local/bin/lua

CMD ["lua", "-v"]
