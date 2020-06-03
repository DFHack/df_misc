local dfhackrpc = Proto("DFHackRPC", "DFHack RPC")

local command_results = {
	[-3] = "LINK_FAILURE",
	[-2] = "NEEDS_CONSOLE",
	[-1] = "NOT_IMPLEMENTED",
	[0] = "OK",
	[1] = "FAILURE",
	[2] = "WRONG_USAGE",
	[3] = "NOT_FOUND"
}

local handshake_client_field = ProtoField.string("dfhackrpc.handshake.client", "Client Handshake")
local handshake_server_field = ProtoField.string("dfhackrpc.handshake.server", "Server Handshake")
local handshake_version_field = ProtoField.int32("dfhackrpc.handshake.version", "Protocol Version")
local header_id_field = ProtoField.int16("dfhackrpc.header.id", "ID", base.DEC)
local header_size_field = ProtoField.int32("dfhackrpc.header.size", "Size", base.DEC)
local header_commandresult_field = ProtoField.int32("dfhackrpc.header.command_result", "Command Result", base.DEC, command_results)

dfhackrpc.fields = {handshake_client_field, handshake_server_field,
	handshake_version_field, header_id_field, header_size_field,
	header_commandresult_field}

local tcp_seqno = Field.new("tcp.seq")
local tcp_stream = Field.new("tcp.stream")

local conversations = {}

function dfhackrpc.init()
	conversations = {}
end

local default_message_ids = {
	-- -1 and -2 are handled specially
	[-3] = {n = "TEXT", i = "dfproto.CoreTextNotification"},
	[-4] = {n = "QUIT", i = "dfproto.EmptyMessage"},
	[0] = {n = "BindMethod", i = "dfproto.CoreBindRequest", o = "dfproto.CoreBindReply"},
	[1] = {n = "RunCommand", i = "dfproto.CoreRunCommandRequest", o = "dfproto.EmptyMessage"}
}

local function read_varint(buffer, offset)
	local n = 0
	while true do
		local b = buffer:range(offset, 1):uint()
		offset = offset + 1

		n = n * 128
		n = n + (b % 128)

		if b < 128 then
			return n, offset
		end
	end
end

local function dfhackrpc_packet_length(tvb, pinfo, offset)
	local id = tvb:range(offset, 2):le_int()
	local size = tvb:range(offset + 4, 4):le_int()
	local full = tvb:range(offset, 8):string()

	if full == "DFHack?\n" or full == "DFHack!\n" then
		return 8 + 4
	end

	if id == -2 then
		return 8
	end

	return 8 + size
end

local function dfhackrpc_dissect_packet(tvb, pinfo, root)
	pinfo.cols.protocol:set("DFHack")
	local tree = root:add_le(dfhackrpc, tvb:range(0, tvb:len()))

	local conversation = conversations[tcp_stream()()]
	if conversation == nil then
		conversation = {
			message_ids = {},
			requests = {}
		}
		for k,v in pairs(default_message_ids) do
			conversation.message_ids[k] = v
		end
		conversations[tcp_stream()()] = conversation
	end

	local magic = tvb:range(0, 8):string()
	if magic == "DFHack?\n" then
		local handshake = tree:append_text(" Handshake")
		handshake:append_text(", Client, Version: " .. tvb:range(8, 4):le_int())
		handshake:add_le(handshake_client_field, tvb:range(0, 8))
		handshake:add_le(handshake_version_field, tvb:range(8, 4))
		return 12
	end
	if magic == "DFHack!\n" then
		local handshake = tree:append_text(" Handshake")
		handshake:append_text(", Server, Version: " .. tvb:range(8, 4):le_int())
		handshake:add_le(handshake_server_field, tvb:range(0, 8))
		handshake:add_le(handshake_version_field, tvb:range(8, 4))
		return 12
	end

	local id = tvb:range(0, 2):le_int()
	local header = tree:append_text(" Header"):set_len(8)
	header:add_le(header_id_field, tvb:range(0, 2))

	local request
	if not pinfo.visited then
		if id >= 0 or id == -4 then
			request = {
				i = id,
				c = tcp_seqno()(),
				s = nil
			}
			table.insert(conversation.requests, request)
		else
			for _,req in ipairs(conversation.requests) do
				if req.s == nil then
					request = req
					if id ~= -3 then
						req.s = tcp_seqno()()
					end
					break
				end
			end
		end
	else 
		if id >= 0 or id == -4 then
			for _,req in ipairs(conversation.requests) do
				if req.c == tcp_seqno()() then
					request = req
					break
				end
			end
		else
			for _,req in ipairs(conversation.requests) do
				request = req
				if req.s ~= nil and req.s >= tcp_seqno()() then
					break
				end
			end
		end
	end
	if request == nil and not pinfo.visited then
		print("expected request for " .. id)
	end

	if id == -2 then
		local result = tvb:range(4, 4):le_int()
		header:append_text(", ID: -2 (FAIL), Result: " .. result .. " (" .. (command_results[result] or "?") .. ")")
		header:add_le(header_commandresult_field, tvb:range(4, 4))
		return 8
	end

	local message_def = conversation.message_ids[request.i]
	local message_name = message_def.n
	local message_type

	if id == -1 then
		message_name = "RESULT(" .. message_name .. ")"
		message_type = message_def.o
	elseif id == -3 then
		message_name = "TEXT(" .. message_name .. ")"
		message_type = conversation.message_ids[-3].i
	else
		message_type = message_def.i
	end

	local payload = tvb:range(8):tvb()
	header:append_text(", ID: " .. id .. " (" .. message_name .. "), Size: " .. payload:len())
	header:add_le(header_size_field, tvb:range(4, 4))
	pinfo.private["pb_msg_type"] = "message," .. message_type
	Dissector.get("protobuf"):call(payload, pinfo, root)

	if not pinfo.visited and request.i == 0 then
		-- heavily simplified (and therefore wrong) protobuf implementation
		local fields = {}
		local offset = 0
		if id == 0 then
			-- bind request
			while offset < payload:len() do
				local fieldNo = (payload:range(offset, 1):uint() - 2) / 8
				offset = offset + 1
				local size
				size, offset = read_varint(payload, offset)
				fields[fieldNo] = payload:range(offset, size):string()
				offset = offset + size
			end
			request.br = {
				n = fields[1],
				i = fields[2],
				o = fields[3]
			}
			if fields[4] then
				request.br.n = fields[4] .. "::" .. fields[1]
			end
		elseif id == -1 then
			-- bind response
			while offset < payload:len() do
				local fieldNo = payload:range(offset, 1):uint() / 8
				offset = offset + 1
				fields[fieldNo], offset = read_varint(payload, offset)
			end
			conversation.message_ids[fields[1]] = request.br
		end
	end

	return tvb:len()
end

function dfhackrpc.dissector(tvb, pinfo, tree)
	dissect_tcp_pdus(tvb, tree, 8, dfhackrpc_packet_length,
		dfhackrpc_dissect_packet)
end

local function dfhackrpc_heuristic(buffer, pinfo, tree)
	if buffer:reported_length_remaining() < 12 then
		return false
	end

	if tcp_seqno()() ~= 1 then
		return false
	end

	local magic = buffer:range(0, 8):string()
	if magic == "DFHack?\n" then
		pinfo.conversation = dfhackrpc
		return true
	end

	return false
end

dfhackrpc:register_heuristic("tcp", dfhackrpc_heuristic)
