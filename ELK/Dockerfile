FROM zeek/zeek:8.0

RUN apt update && apt install -y cmake g++ make git libpcap-dev

COPY spicy-iec104 /opt/spicy-iec104

RUN cd /opt/spicy-iec104 \
 && cmake . \
 && make \
 && make install