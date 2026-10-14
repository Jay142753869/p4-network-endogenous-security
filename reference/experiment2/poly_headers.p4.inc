/*
 * 课堂接口示例：复制到 polymorphic.p4 的常量和 header 区域后再补充 parser。
 * 本文件是片段，不是独立 P4 程序。
 */
const bit<16> POLY_MAGIC         = 0x504f; // ASCII "PO"
const bit<8>  POLY_IP_PROTOCOL   = 253;
const bit<16> POLY_UDP_PORT      = 5000;
const bit<16> POLY_MCAST_GROUP   = 10;

const bit<8> MODE_IPV4 = 1;
const bit<8> MODE_IPV6 = 2;
const bit<8> MODE_SR   = 3;

header polyShim_t {
    bit<16> magic;
    bit<8>  direction;       // 0: h1 -> h2, 1: h2 -> h1
    bit<32> sequence_number;
    bit<8>  modality_id;
    bit<32> source_crc32;
    bit<16> inner_ether_type;
}

header protectedData_t {
    bit<128> value;
}

