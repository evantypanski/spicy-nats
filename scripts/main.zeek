@load base/protocols/conn/removal-hooks

module NATS;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register NATS for.
	const ports = {
		# TODO: Replace with actual port(s).
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

		# TODO: Adapt subsequent fields as needed.

		## Request-side payload.
		request: string &optional &log;
		## Response-side payload.
		reply: string &optional &log;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Default hook into NATS logging.
	global log_nats: event(rec: Info);

	## NATS finalization hook.
	global finalize_nats: Conn::RemovalHook;
}

redef record connection += {
	nats: Info &optional;
};

redef likely_server_ports += { ports };

# TODO: If you're going to send file data into the file analysis framework, you
# need to provide a file handle function. This is a simple example that's
# sufficient if the protocol only transfers a single, complete file at a time.
#
# function get_file_handle(c: connection, is_orig: bool): string
# 	{
# 	return cat(Analyzer::ANALYZER_NATS, c$start_time, c$id, is_orig);
# 	}

event zeek_init() &priority=5
	{
	Log::create_stream(NATS::LOG, [$columns=Info, $ev=log_nats, $path="nats", $policy=log_policy]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_NATS, ports);

	# TODO: To activate the file handle function above, uncomment this.
	# Files::register_protocol(Analyzer::ANALYZER_NATS, [$get_file_handle=NATS::get_file_handle ]);
	}

# Initialize logging state.
hook set_session(c: connection)
	{
	if ( c?$nats )
		return;

	c$nats = Info($ts=network_time(), $uid=c$uid, $id=c$id);
	Conn::register_removal_hook(c, finalize_nats);
	}

function emit_log(c: connection)
	{
	if ( ! c?$nats )
		return;

	Log::write(NATS::LOG, c$nats);
	delete c$nats;
	}

# Example event defined in nats.evt.
event NATS::request(c: connection, is_orig: bool, payload: string)
	{
	hook set_session(c);

	local info = c$nats;
	info$request = payload;
	}

# Example event defined in nats.evt.
event NATS::reply(c: connection, is_orig: bool, payload: string)
	{
	hook set_session(c);

	local info = c$nats;
	info$reply = payload;
	}

hook finalize_nats(c: connection)
	{
	emit_log(c);
	}
