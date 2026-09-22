FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN git clone --depth 1 https://github.com/bug-ops/exarch.git exarch
COPY build.sh $SRC/

WORKDIR $SRC/exarch
