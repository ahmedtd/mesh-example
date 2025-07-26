# This Dockerfile assumes that the binary has already been built using the go
# toolchain and placed at cmd/meshtool/meshtool

FROM gcr.io/distroless/static-debian11

COPY ./meshtool /meshtool

CMD ["/meshtool"]