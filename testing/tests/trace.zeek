# @TEST-DOC: Test Zeek parsing a trace file through the NATS analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/tcp-port-12345.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff nats.log

# TODO: Adapt as suitable. The example only checks the output of the event
# handlers.

event NATS::request(c: connection, is_orig: bool, payload: string)
    {
    print fmt("Testing NATS: [request] %s %s", c$id, payload);
    }

event NATS::reply(c: connection, is_orig: bool, payload: string)
    {
    print fmt("Testing NATS: [reply] %s %s", c$id, payload);
    }
