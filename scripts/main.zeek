@load base/protocols/conn/removal-hooks

module NATS;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register NATS for.
	const ports = {
		4222/tcp,
	} &redef;

	## Record type containing the column fields of the NATS log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;

		## The command executed.
		command: string &optional &log;
		## The payload of the command.
		payload: string &optional &log;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Default hook into NATS logging.
	global log_nats: event(rec: Info);
}

redef record connection += {
	nats: Info &optional;
};

redef likely_server_ports += {ports};

event zeek_init() &priority=5
	{
	Log::create_stream(NATS::LOG, [$columns=Info, $ev=log_nats, $path="nats",
	    $policy=log_policy]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_NATS, ports);
	}

# Initialize logging state.
hook set_session(c: connection)
	{
	if ( c?$nats )
		return;

	c$nats = Info($ts=network_time(), $uid=c$uid, $id=c$id);
	}

function emit_log(c: connection)
	{
	if ( ! c?$nats )
		return;

	Log::write(NATS::LOG, c$nats);
	delete c$nats;
	}

event NATS::connect(c: connection, keyval: table[string] of string)
	{
	hook set_session(c);

	local info = c$nats;
	info$command = "CONNECT";
	#info$payload = keyval;
	emit_log(c);
	}

event NATS::info_message(c: connection, keyval: table[string] of string)
	{
	hook set_session(c);

	local info = c$nats;
	info$command = "INFO";
	#info$payload = keyval;
	emit_log(c);
	}

event NATS::error(c: connection, message: string)
	{
	hook set_session(c);

	local info = c$nats;
	info$command = "ERR";
	info$payload = message;
	emit_log(c);
	}
