# @TEST-DOC: Test Zeek parsing a trace file through the NATS analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/simple-nats.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff nats.log

event NATS::request(c: connection, is_orig: bool, message: NATS::ClientData)
    {
    print fmt("Testing NATS: [request] %s %s", c$id, message);
    }

event NATS::reply(c: connection, is_orig: bool, message: NATS::ServerData)
    {
    print fmt("Testing NATS: [reply] %s %s", c$id, message);
    }
