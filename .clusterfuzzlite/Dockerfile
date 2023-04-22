FROM gcr.io/oss-fuzz-base/base-builder-rust:v1
RUN apt-get update && apt-get install -y make autoconf automake libtool
COPY . $SRC/pe-parser
WORKDIR pe-parser
COPY .clusterfuzzlite/build.sh $SRC/
