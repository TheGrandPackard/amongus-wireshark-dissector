amongus_protocol = Proto("AmongUs",  "Among Us Protocol")

send_option = ProtoField.uint8("amongus.send_option", "Send Option", base.DEC)
send_option_name = ProtoField.string("amongus.send_option_name", "Send Option Name", base.ASCII)
sequence = ProtoField.uint16("amongus.sequence", "Sequence", base.DEC)
message_length = ProtoField.uint16("amongus.message_length", "Message Length", base.DEC)
opcode = ProtoField.uint8("amongus.opcode", "Op Code", base.DEC)
opcode_name = ProtoField.string("amongus.opcode_name", "Op Code Name", base.ASCII)
disconnect_reason = ProtoField.uint8("amongus.disconnect_reason", "Disconnect Reason", base.DEC)
disconnect_reason_name = ProtoField.string("amongus.disconnect_reason_name", "Disconnect Reason Name", base.ASCII)
game_data_opcode = ProtoField.uint8("amongus.gamd_data_opcode", "Game Data Op Code", base.DEC)
game_data_opcode_name = ProtoField.string("amongus.gamd_data_opcode_name", "Game Data Op Code Name", base.ASCII)

client_version = ProtoField.uint32("amongus.client_version", "Client Version", base.DEC)
client_version_string = ProtoField.string("amongus.client_version_string", "Client Version String", base.ASCII)
player_name = ProtoField.string("amongus.player_name", "Player Name", base.ASCII)
player_id = ProtoField.uint32("amongus.player_id", "Player ID", base.DEC)

server_name = ProtoField.string("amongus.server_name", "Server Name", base.ASCII)
host_id = ProtoField.uint32("amongus.host_id", "Host ID", base.DEC)
ip_address = ProtoField.ipv4("amongus.ip_address", "IP Address")
port = ProtoField.uint8("amongus.port", "Port", base.DEC)
game_version = ProtoField.uint8("amongus.game_version", "Game Version", base.DEC)
max_players = ProtoField.uint8("amongus.max_players", "Max Players", base.DEC)
players = ProtoField.uint8("amongus.players", "Players", base.DEC)
language = ProtoField.uint32("amongus.language", "Language", base.DEC)
map = ProtoField.uint8("amongus.map", "Map", base.DEC)
age = ProtoField.uint8("amongus.age", "Age", base.DEC)
player_speed_mod = ProtoField.float("amongus.player_speed_mod", "Player Speed Mod", base.DEC)
crew_light_mod = ProtoField.float("amongus.crew_light_mod", "Crew Light Mod", base.DEC)
impostor_light_mod = ProtoField.float("amongus.impostor_light_mod", "Impostor Light Mod", base.DEC)
kill_cooldown = ProtoField.float("amongus.kill_cooldown", "Kill Cooldown", base.DEC)
num_common_tasks = ProtoField.uint8("amongus.num_common_tasks", "Num Common Tasks", base.DEC)
num_long_tasks = ProtoField.uint8("amongus.num_long_tasks", "Num Long Tasks", base.DEC)
num_short_tasks = ProtoField.uint8("amongus.num_short_tasks", "Num Short Tasks", base.DEC)
num_emergency_meetings = ProtoField.int32("amongus.num_emergency_meetings", "Num Emergency Meetings", base.DEC)
num_imposters = ProtoField.uint8("amongus.num_imposters", "Num Imposters", base.DEC)
kill_distance = ProtoField.uint8("amongus.kill_distance", "Kill Distance", base.DEC)
discussion_time = ProtoField.int32("amongus.discussion_time", "Discussion Time", base.DEC)
voting_time = ProtoField.int32("amongus.voting_time", "Voting Time", base.DEC)
is_defaults = ProtoField.uint8("amongus.is_defaults", "Is Defaults", base.DEC)
emergency_cooldown = ProtoField.uint8("amongus.emergency_cooldown", "Emergency Cooldown", base.DEC)
game_code = ProtoField.int32("amongus.game_code", "Game Code", base.DEC)
game_code_string = ProtoField.string("amongus.game_code_string", "Game Code String", base.ASCII)
alter_game_type = ProtoField.uint8("amongus.alter_game_type", "Alter Game Type", base.DEC)
alter_game_value = ProtoField.uint8("amongus.alter_game_value", "Alter Game Value", base.DEC)

banned = ProtoField.uint8("amongus.banned", "Banned", base.DEC)

amongus_protocol.fields = { 
    send_option, send_option_name, 
    sequence, message_length, 
    opcode, opcode_name,
    disconnect_reason,
    disconnect_reason_name,
    game_data_opcode,
    game_data_opcode_name,
    client_version, 
    client_version_string,
    player_name,
    game_version,
    max_players,
    players,
    language,
    map,
    player_speed_mod,
    crew_light_mod,
    impostor_light_mod,
    kill_cooldown,
    num_common_tasks,
    num_long_tasks,
    num_short_tasks,
    num_emergency_meetings,
    num_imposters,
    kill_distance,
    discussion_time,
    voting_time,
    is_defaults,
    emergency_cooldown,
    game_code,
    game_code_string,
    player_id,
    host_id,
    server_name,
    ip_address,
    port,
    age,
    banned,
    alter_game_type,
    alter_game_value
}

function amongus_protocol.dissector(buffer, pinfo, tree)
  local length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = amongus_protocol.name
  local subtree = tree:add(amongus_protocol, buffer(), "Among Us Protocol Data")

  -- every packet starts with a send option which determines how to dissect the rest of the packet
  local send_option_value = buffer(0,1):uint()
  subtree:add(send_option, buffer(0,1))
  subtree:add(send_option_name, get_send_option_name(send_option_value))

  -- where to look for the opcode and data
  local opcode_offset = 5
  local data_offset = 6

  if send_option_value == 0 then -- Unreliable Data
    subtree:add_le(message_length, buffer(1,2))
    opcode_offset = 3
    data_offset = 4
  elseif send_option_value == 1 then -- Reliable Data
    subtree:add(sequence, buffer(1,2))
    subtree:add_le(message_length, buffer(3,2))
  elseif send_option_value == 8 then -- Hello
    subtree:add(sequence, buffer(1,2))
    subtree:add_le(client_version, buffer(4,4))
    local client_version_value = buffer(4,4):le_int()
    subtree:add(client_version_string, IntToGameVersion(client_version_value))
    local name_length = buffer(8,1):uint()
    subtree:add(player_name, buffer(9,name_length))
    opcode_offset = -1
    data_offset = -1
  elseif send_option_value == 9 then -- Disconnect
    opcode_offset = -1
    data_offset = -1
    if length > 1 then
        subtree:add(disconnect_reason, buffer(5, 1))
        local disconnect_reason_length = buffer(6,1):uint()
        subtree:add(disconnect_reason_name, buffer(7,disconnect_reason_length))
    end
  elseif send_option_value == 10 then -- Acknowledgement
    subtree:add(sequence, buffer(1,2))
    -- The last byte of Acknowledgement is likely part of Hazel netcode and not useful
    opcode_offset = -1
    data_offset = -1
  elseif send_option_value == 11 then -- Fragment
    opcode_offset = -1
    data_offset = -1
  elseif send_option_value == 12 then -- Ping
    subtree:add(sequence, buffer(1,2))
    opcode_offset = -1
    data_offset = -1
  end
  
  -- If opcode offset is set to -1, then there is no opcode in the packet
  if opcode_offset > -1 then
    subtree:add(opcode, buffer(opcode_offset,1))
    opcode_value = buffer(opcode_offset,1):uint()
    subtree:add(opcode_name, get_opcode_name(opcode_value))
  end

  -- If data offset is set to -1, then there is no data in the packet
  if data_offset > -1 then 
    if opcode_value ==  0 then  -- OP_HOSTGAME
        dissect_hostgame(buffer, data_offset, pinfo, subtree)
    elseif opcode_value ==  1 then  -- OP_JOINGAME
        dissect_joingame(buffer, data_offset, pinfo, subtree)
    elseif opcode_value ==  2 then  -- OP_STARTGAME
        dissect_startgame(buffer, data_offset, pinfo, subtree)
    elseif opcode_value ==  3 then  -- OP_REMOVEGAME
        dissect_removegame(buffer, data_offset, pinfo, subtree)
    elseif opcode_value ==  4 then  -- OP_REMOVEPLAYER
        dissect_removeplayer(buffer, data_offset, pinfo, subtree)
    elseif opcode_value ==  5 then  -- OP_GAMEDATA
        dissect_gamedata(buffer, data_offset, pinfo, subtree)
    elseif opcode_value ==  6 then  -- OP_GAMEDATATO
        dissect_gamedatato(buffer, data_offset, pinfo, subtree)
    elseif opcode_value ==  7 then  -- OP_JOINEDGAME
        dissect_joinedgame(buffer, data_offset, pinfo, subtree)
    elseif opcode_value ==  8 then  -- OP_ENDGAME
        dissect_endgame(buffer, data_offset, pinfo, subtree)
    elseif opcode_value ==  9 then  -- OP_GETGAMELIST
        dissect_getgamelist(buffer, data_offset, pinfo, subtree)
    elseif opcode_value == 10 then  -- OP_ALTERGAME
        dissect_altergame(buffer, data_offset, pinfo, subtree)
    elseif opcode_value == 11 then  -- OP_KICKPLAYER
        dissect_kickplayer(buffer, data_offset, pinfo, subtree)
    elseif opcode_value == 12 then  -- OP_WAITFORHOST
        dissect_waitforhost(buffer, data_offset, pinfo, subtree)
    elseif opcode_value == 13 then  -- OP_REDIRECT
        dissect_redirect(buffer, data_offset, pinfo, subtree)
    elseif opcode_value == 14 then  -- OP_RESELECTSERVER
        dissect_reselectserver(buffer, data_offset, pinfo, subtree)
    elseif opcode_value == 16 then  -- OP_GETGAMELISTV2
        dissect_getgamelistv2(buffer, data_offset, pinfo, subtree)
    end
  end
end

function get_send_option_name(send_option)
    local send_option_name = "Unknown"

        if send_option ==  0 then send_option_name = "Unreliable Data"
    elseif send_option ==  1 then send_option_name = "Reliable Data"
    elseif send_option ==  8 then send_option_name = "Hello"
    elseif send_option ==  9 then send_option_name = "Disconnect"
    elseif send_option == 10 then send_option_name = "Acknowledgement"
    elseif send_option == 11 then send_option_name = "Fragment"
    elseif send_option == 12 then send_option_name = "Ping"
    end
    
    return send_option_name
end

function get_opcode_name(opcode)
    local opcode_name = "Unknown"
  
        if opcode ==  0 then opcode_name = "OP_HOSTGAME"
    elseif opcode ==  1 then opcode_name = "OP_JOINGAME"
    elseif opcode ==  2 then opcode_name = "OP_STARTGAME"
    elseif opcode ==  3 then opcode_name = "OP_REMOVEGAME"
    elseif opcode ==  4 then opcode_name = "OP_REMOVEPLAYER"
    elseif opcode ==  5 then opcode_name = "OP_GAMEDATA"
    elseif opcode ==  6 then opcode_name = "OP_GAMEDATATO"
    elseif opcode ==  7 then opcode_name = "OP_JOINEDGAME"
    elseif opcode ==  8 then opcode_name = "OP_ENDGAME"
    elseif opcode ==  9 then opcode_name = "OP_GETGAMELIST"
    elseif opcode == 10 then opcode_name = "OP_ALTERGAME"
    elseif opcode == 11 then opcode_name = "OP_KICKPLAYER"
    elseif opcode == 12 then opcode_name = "OP_WAITFORHOST"
    elseif opcode == 13 then opcode_name = "OP_REDIRECT"
    elseif opcode == 14 then opcode_name = "OP_RESELECTSERVER"
    elseif opcode == 16 then opcode_name = "OP_GETGAMELISTV2" 
    end
  
    return opcode_name
end

function get_game_data_opcode_name(opcode)
    local opcode_name = "Unknown"
  
        if opcode == 11 then opcode_name = "OP_PLAYERMOVEMENT"
    end
  
    return opcode_name
end

function get_disconnect_reason_name(disconnect_reason)
    local disconnect_reason_name = "Unknown"

    if disconnect_reason == 0 then disconnect_reason_name = "ExitGame"  
    elseif disconnect_reason == 1 then disconnect_reason_name = "GameFull" -- The game you tried to join is full. Check with the host to see if you can join next round.
    elseif disconnect_reason == 2 then disconnect_reason_name = "GameStarted" -- The game you tried to join already started. Check with the host to see if you can join next round.
    elseif disconnect_reason == 3 then disconnect_reason_name = "GameMissing" -- Could not find the game you're looking for.
    elseif disconnect_reason == 4 then disconnect_reason_name = "CustomMessage1"
    elseif disconnect_reason == 5 then disconnect_reason_name = "IncorrectVersion" -- You are running an older version of the game. Please update to play with others.
    elseif disconnect_reason == 6 then disconnect_reason_name = "Banned" -- You cannot rejoin that room. You were banned
    elseif disconnect_reason == 7 then disconnect_reason_name = "Kicked" -- You can rejoin if the room hasn't started. You were kicked
    elseif disconnect_reason == 8 then disconnect_reason_name = "Custom"
    elseif disconnect_reason == 9 then disconnect_reason_name = "InvalidName" -- Server refused username: %USERNAME%
    elseif disconnect_reason == 10 then disconnect_reason_name = "Hacking" -- You were banned for hacking. Please stop.
    elseif disconnect_reason == 16 then disconnect_reason_name = "Destroy"
    elseif disconnect_reason == 18 then disconnect_reason_name = "IncorrectGame"
    elseif disconnect_reason == 17 then disconnect_reason_name = "Error" -- You disconnected from the server.
    elseif disconnect_reason == 19 then disconnect_reason_name = "ServerRequest" -- The server stopped this game. Possibly due to inactivity.
    elseif disconnect_reason == 20 then disconnect_reason_name = "ServerFull" -- The Among Us servers are overloaded. Sorry! Please try again later!
    elseif disconnect_reason == 207 then disconnect_reason_name = "FocusLostBackground"
    elseif disconnect_reason == 208 then disconnect_reason_name = "IntentionalLeaving"
    elseif disconnect_reason == 209 then disconnect_reason_name = "FocusLost"
    elseif disconnect_reason == 210 then disconnect_reason_name = "NewConnection"
    end

    return disconnect_reason_name
end

function dissect_hostgame(buffer, data_offset, pinfo, tree)
    local length = buffer:len()
    if length == 10 then 
        local host_game_subtree = tree:add(amongus_protocol, buffer(), "Host Game Response")
        host_game_subtree:add_le(game_code, buffer(data_offset, 4))
        local game_code_value = buffer(data_offset,4):le_int()
        host_game_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))
    else  
      local host_game_subtree = tree:add(amongus_protocol, buffer(), "Host Game Request")      
      host_game_subtree:add(game_version, buffer(data_offset+1, 1))
      host_game_subtree:add(max_players, buffer(data_offset+2, 1))
      host_game_subtree:add_le(language, buffer(data_offset+3, 4))
      host_game_subtree:add(map, buffer(data_offset+7, 1))
      host_game_subtree:add_le(player_speed_mod, buffer(data_offset+8, 4))
      host_game_subtree:add_le(crew_light_mod, buffer(data_offset+12, 4))
      host_game_subtree:add_le(impostor_light_mod, buffer(data_offset+16, 4))
      host_game_subtree:add_le(kill_cooldown, buffer(data_offset+20, 4))
      host_game_subtree:add(num_common_tasks, buffer(data_offset+24, 1))
      host_game_subtree:add(num_long_tasks, buffer(data_offset+25, 1))
      host_game_subtree:add(num_short_tasks, buffer(data_offset+26, 1))
      host_game_subtree:add_le(num_emergency_meetings, buffer(data_offset+27, 4))
      host_game_subtree:add(num_imposters, buffer(data_offset+31, 1))
      host_game_subtree:add(kill_distance, buffer(data_offset+32, 1))
      host_game_subtree:add_le(discussion_time, buffer(data_offset+33, 4))
      host_game_subtree:add_le(voting_time, buffer(data_offset+37, 4))
      host_game_subtree:add(is_defaults, buffer(data_offset+41, 1))
      host_game_subtree:add(emergency_cooldown, buffer(data_offset+42, 1))
    end
end

function dissect_joingame(buffer, data_offset, pinfo, tree)
    length = buffer:len()
    if length >= 11 then 
        local join_game_subtree = tree:add(amongus_protocol, buffer(), "Join Game Request")
        join_game_subtree:add_le(game_code, buffer(data_offset, 4))
        local game_code_value = buffer(data_offset,4):le_int()
        join_game_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))        
        -- TODO: Dissect last byte that always seems to be 0x07
    else
        local join_game_error_subtree = tree:add(amongus_protocol, buffer(), "Join Game Error")
        join_game_error_subtree:add(disconnect_reason, buffer(data_offset, 1))
        local disconnect_reason_value = buffer(data_offset, 1):uint()
        join_game_error_subtree:add(disconnect_reason_name, get_disconnect_reason_name(disconnect_reason_value))
    end
end

function dissect_startgame(buffer, data_offset, pinfo, tree)
    local start_game_subtree = tree:add(amongus_protocol, buffer(), "Start Game")
    start_game_subtree:add_le(game_code, buffer(data_offset, 4))
    local game_code_value = buffer(data_offset,4):le_int()
    start_game_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))
end

function dissect_removegame(buffer, data_offset, pinfo, tree)
    -- Remove Game is either deprectated or never used
end

function dissect_removeplayer(buffer, data_offset, pinfo, tree)
    local remove_player_subtree = tree:add(amongus_protocol, buffer(), "Remove Player Request")
    remove_player_subtree:add_le(game_code, buffer(data_offset, 4))
    local game_code_value = buffer(data_offset,4):le_int()
    remove_player_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))
    remove_player_subtree:add(player_id, buffer(data_offset+4, 4))
end

function dissect_gamedata(buffer, data_offset, pinfo, tree)
    local game_data_subtree = tree:add(amongus_protocol, buffer(), "Game Data")
    game_data_subtree:add_le(game_code, buffer(data_offset, 4))
    local game_code_value = buffer(data_offset,4):le_int()
    game_data_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))

    local data_offset = data_offset + 4
    dissect_game_data_packet(buffer, data_offset, pinfo, game_data_subtree)
end

function dissect_gamedatato(buffer, data_offset, pinfo, tree)
    local game_data_to_subtree = tree:add(amongus_protocol, buffer(), "Game Data To")
    game_data_to_subtree:add_le(game_code, buffer(data_offset, 4))
    local game_code_value = buffer(data_offset,4):le_int()
    game_data_to_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))
    game_data_to_subtree:add(player_id, buffer(data_offset+4, 4))

    local data_offset = data_offset + 4
    dissect_game_data_packet(buffer, data_offset, pinfo, game_data_to_subtree)
end

function dissect_game_data_packet(buffer, data_offset, pinfo, tree) 
    tree:add(game_data_opcode, buffer(data_offset, 1))
    local game_data_opcode_value = buffer(data_offset,1):uint()
    tree:add(game_data_opcode_name, get_game_data_opcode_name(game_data_opcode_value))
    -- TODO: Dissect game data packets

    -- 0x0b movement position update
    -- 0x00 0x01 0x06 - message header and a player id?
    -- movement update sequence uint16 little endian
    -- x position int16? endianness?
    -- y position int16? endianness?
    -- 0xff 0x7f 0xff 0x7f
    
    -- 0x0b movement position update
    -- 0x00 0x01 0x09 - message header and a player id?
    -- movement update sequence uint16 little endian
    -- x position int16? endianness?
    -- y position int16? endianness?
    -- 0xff 0x87 0xff 0x7f
end

function dissect_joinedgame(buffer, data_offset, pinfo, tree)
    local joined_game_subtree = tree:add(amongus_protocol, buffer(), "Joined Game Request")
    joined_game_subtree:add_le(game_code, buffer(data_offset, 4))
    local game_code_value = buffer(data_offset,4):le_int()
    joined_game_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))
    joined_game_subtree:add(player_id, buffer(data_offset+4, 4))
    joined_game_subtree:add(host_id, buffer(data_offset+8, 4))
    joined_game_subtree:add(players, buffer(data_offset+12, 1))
    -- TODO: Parse array of packed player ids
    -- This packet has an alter game packet at the end of it
    -- Skip 3 bytes for length and opcode
    dissect_altergame(buffer, data_offset+16, pinfo, tree)
end

function dissect_endgame(buffer, data_offset, pinfo, tree)
    local end_game_subtree = tree:add(amongus_protocol, buffer(), "End Game")
    end_game_subtree:add_le(game_code, buffer(data_offset, 4))
    local game_code_value = buffer(data_offset,4):le_int()
    end_game_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))
end

function dissect_getgamelist(buffer, data_offset, pinfo, tree)
    -- Get Game List V1 is deprecated
end

function dissect_altergame(buffer, data_offset, pinfo, tree)
    local alter_game_subtree = tree:add(amongus_protocol, buffer(), "Alter Game")
    alter_game_subtree:add_le(game_code, buffer(data_offset, 4))
    local game_code_value = buffer(data_offset,4):le_int()
    alter_game_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))
    alter_game_subtree:add(alter_game_type, buffer(data_offset+4, 1))
    alter_game_subtree:add(alter_game_value, buffer(data_offset+5, 1))
end

function dissect_kickplayer(buffer, data_offset, pinfo, tree)
    local kick_player_subtree = tree:add(amongus_protocol, buffer(), "Kick Player")
    kick_player_subtree:add_le(game_code, buffer(data_offset, 4))
    local game_code_value = buffer(data_offset,4):le_int()
    kick_player_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))
    kick_player_subtree:add(player_id, buffer(data_offset+4, 3))
    -- TODO: Parse packed player id    
    kick_player_subtree:add(banned, buffer(data_offset+7, 1))
end

function dissect_waitforhost(buffer, data_offset, pinfo, tree)
    local wait_for_host_subtree = tree:add(amongus_protocol, buffer(), "Wait For Host")
    wait_for_host_subtree:add_le(game_code, buffer(data_offset, 4))
    local game_code_value = buffer(data_offset,4):le_int()
    wait_for_host_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))
    wait_for_host_subtree:add(player_id, buffer(data_offset+4, 4))
end

function dissect_redirect(buffer, data_offset, pinfo, tree)
    local redirect_subtree = tree:add(amongus_protocol, buffer(), "Redirect")
    redirect_subtree:add(ip_address, buffer(data_offset, 4))
    redirect_subtree:add_le(port, buffer(data_offset+4, 2))
end

function dissect_reselectserver(buffer, data_offset, pinfo, tree)
    local redirect_subtree = tree:add(amongus_protocol, buffer(), "Reselect Server")    
    local server_length = buffer(data_offset+1,1):uint()

    local offset = data_offset+2
    for i = 1,server_length,1 
    do
        local server_subtree = redirect_subtree:add(amongus_protocol, buffer(), "Server " .. i)    
        local message_length = buffer(offset,2):le_uint()
        local name_length = buffer(offset+3,1):uint()
        server_subtree:add(server_name, buffer(offset+4,name_length))
        server_subtree:add(ip_address, buffer(offset+4+name_length, 4))
        server_subtree:add_le(port, buffer(offset+4+name_length+4, 2))
        offset = offset + 2 + message_length + 1
    end

end

function dissect_getgamelistv2(buffer, data_offset, pinfo, tree)
    local length = buffer:len()
    if length == 50 then 
        local get_game_list_request_subtree = tree:add(amongus_protocol, buffer(), "Get Game List V2 Request")
        get_game_list_request_subtree:add(game_version, buffer(data_offset+2, 1))
        get_game_list_request_subtree:add(max_players, buffer(data_offset+3, 1))
        get_game_list_request_subtree:add_le(language, buffer(data_offset+4, 4))
        get_game_list_request_subtree:add(map, buffer(data_offset+8, 1))
        get_game_list_request_subtree:add_le(player_speed_mod, buffer(data_offset+9, 4))
        get_game_list_request_subtree:add_le(crew_light_mod, buffer(data_offset+13, 4))
        get_game_list_request_subtree:add_le(impostor_light_mod, buffer(data_offset+17, 4))
        get_game_list_request_subtree:add_le(kill_cooldown, buffer(data_offset+21, 4))
        get_game_list_request_subtree:add(num_common_tasks, buffer(data_offset+25, 1))
        get_game_list_request_subtree:add(num_long_tasks, buffer(data_offset+26, 1))
        get_game_list_request_subtree:add(num_short_tasks, buffer(data_offset+27, 1))
        get_game_list_request_subtree:add_le(num_emergency_meetings, buffer(data_offset+28, 4))
        get_game_list_request_subtree:add(num_imposters, buffer(data_offset+32, 1))
        get_game_list_request_subtree:add(kill_distance, buffer(data_offset+33, 1))
        get_game_list_request_subtree:add_le(discussion_time, buffer(data_offset+34, 4))
        get_game_list_request_subtree:add_le(voting_time, buffer(data_offset+38, 4))
        get_game_list_request_subtree:add(is_defaults, buffer(data_offset+42, 1))
        get_game_list_request_subtree:add(emergency_cooldown, buffer(data_offset+43, 1))
    else 
        local get_game_list_subtree_response = tree:add(amongus_protocol, buffer(), "Get Game List V2 Response")
        local game_length = buffer(data_offset,2):le_uint()

        local i = 1
        local offset = data_offset+2
        while offset < game_length+data_offset+2
        do
            local server_subtree = get_game_list_subtree_response:add(amongus_protocol, buffer(), "Server " .. i)    

            local message_length = buffer(offset+1,2):le_uint()
            server_subtree:add(ip_address, buffer(offset+4, 4))
            server_subtree:add_le(port, buffer(offset+8, 2))
            server_subtree:add_le(game_code, buffer(offset+10, 4))
            local game_code_value = buffer(offset+10,4):le_int()
            server_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))
            local name_length = buffer(offset+14,1):uint()
            server_subtree:add(server_name, buffer(offset+15,name_length))
            server_subtree:add(players, buffer(offset+15+name_length, 1))
            local age_length = 2
            server_subtree:add(age, buffer(offset+15+name_length+1, age_length))
            -- TODO: Parse packed age
            server_subtree:add(map, buffer(offset+15+name_length+1+age_length, 1))
            server_subtree:add(num_imposters, buffer(offset+15+name_length+1+age_length+1, 1))
            server_subtree:add(max_players, buffer(offset+15+name_length+1+age_length+2, 1))

            i = i + 1
            offset = offset + message_length + 3
        end
    end
end

function IntToGameCodeV2(code)
    local gameCodeV2 = 'QWXRTYLPESDFGHUJKZOCVBINMA'
    local a = bit32.band(code, 0x3FF)
    local b = bit32.rshift(code,10) 
    b = bit32.band(b, 0xFFFFF)

    out1 = string.sub(gameCodeV2, 1 + math.floor(a%26), 1 + math.floor(a%26))
    out2 = string.sub(gameCodeV2, 1 + math.floor(a/26), 1 + math.floor(a/26))
    out3 = string.sub(gameCodeV2, 1 + math.floor(b%26), 1 + math.floor(b%26))
    out4 = string.sub(gameCodeV2, 1 + math.floor(b/26%26), 1 + math.floor(b/26%26))
    out5 = string.sub(gameCodeV2, 1 + math.floor(b/(26*26)%26), 1 + math.floor(b/(26*26)%26))
    out6 = string.sub(gameCodeV2, 1 + math.floor(b/(26*26*26)%26), 1 + math.floor(b/(26*26*26)%26))
    
    return out1 .. out2 .. out3 .. out4 .. out5 .. out6
end

function IntToGameVersion(version)
    print(year)
    local year = math.floor(version / 25000)
    print(year)
    local month = math.floor((version - math.floor(year * 25000)) / 1800)
    print(month)
    local day = math.floor((version - math.floor(year * 25000) - math.floor(month * 1800)) / 50)
    print(day)

    return year .. "." .. month .. "." .. day
end

-- TODO: function ReadPackedInt() end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(22023, amongus_protocol)
udp_port:add(22323, amongus_protocol)
udp_port:add(22623, amongus_protocol)
udp_port:add(22723, amongus_protocol)
udp_port:add(22823, amongus_protocol)
udp_port:add(54237, amongus_protocol)
udp_port:add(55837, amongus_protocol)