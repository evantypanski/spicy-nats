# @TEST-DOC: Test Zeek parsing a trace file through the NATS analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/simple-nats.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff nats.log

event NATS::connect(c: connection, keyval: table[string] of string)
	{
	print "CONNECT command content:";
	for ( key, val in keyval )
		{
		print fmt("%s -> %s", key, val);
		}

	print "DONE";
	}

event NATS::info_message(c: connection, keyval: table[string] of string)
	{
	print "INFO command content:";
	for ( key, val in keyval )
		{
		print fmt("%s -> %s", key, val);
		}

	print "DONE";
	}
