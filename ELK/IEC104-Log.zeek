@load base/protocols/conn

module IEC104;
export {
    redef enum Log::ID += { LOG };
}

type Info: record {
    ts: time &log;
    uid: string &log;
    orig_h: addr &log;
    resp_h: addr &log;
    type_id: count &log &optional;
    cot: count &log &optional;
    ioa: count &log &optional;
};

event zeek_init() {
    Log::create_stream(LOG, [$columns=Info, $path="iec104"]);
}

event IEC104::asdu(uid: string, c: connection, type_id: count, cot: count, ioa: count) {
    Log::write(LOG, [
        $ts=network_time(),
        $uid=uid,
        $orig_h=c$id$orig_h,
        $resp_h=c$id$resp_h,
        $type_id=type_id,
        $cot=cot,
        $ioa=ioa
    ]);
}