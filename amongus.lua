amongus_protocol = Proto("AmongUs",  "Among Us Protocol")

send_option = ProtoField.uint8("amongus.send_option", "Send Option", base.DEC)
send_option_name = ProtoField.string("amongus.send_option_name", "Send Option Name", base.ASCII)
sequence = ProtoField.uint16("amongus.sequence", "Sequence", base.DEC)
message_length = ProtoField.uint16("amongus.message_length", "Message Length", base.DEC)
opcode = ProtoField.uint8("amongus.opcode", "Op Code", base.DEC)
opcode_name = ProtoField.string("amongus.opcode_name", "Op Code Name", base.ASCII)
disconnect_reason = ProtoField.uint8("amongus.disconnect_reason", "Disconnect Reason", base.DEC)
client_version = ProtoField.uint32("amongus.client_version", "Client Version", base.DEC)
player_name = ProtoField.string("amongus.player_name", "Player Name", base.ASCII)
max_players = ProtoField.uint8("amongus.max_players", "Max Players", base.DEC)
players = ProtoField.uint8("amongus.players", "Players", base.DEC)
language = ProtoField.uint16("amongus.language", "Language", base.DEC)
map = ProtoField.uint8("amongus.map", "Map", base.DEC)
num_imposters = ProtoField.uint8("amongus.num_imposters", "Num Imposters", base.DEC)
game_code = ProtoField.int32("amongus.game_code", "Game Code", base.DEC)
game_code_string = ProtoField.string("amongus.game_code_string", "Game Code String", base.ASCII)
player_id = ProtoField.uint32("amongus.player_id", "Player ID", base.DEC)
host_id = ProtoField.uint32("amongus.host_id", "Host ID", base.DEC)
alter_game_type = ProtoField.uint8("amongus.alter_game_type", "Alter Game Type", base.DEC)
alter_game_value = ProtoField.uint8("amongus.alter_game_value", "Alter Game Value", base.DEC)
server_name = ProtoField.string("amongus.server_name", "Server Name", base.ASCII)
ip_address = ProtoField.ipv4("amongus.ip_address", "IP Address")
port = ProtoField.uint8("amongus.port", "Port", base.DEC)
age = ProtoField.uint8("amongus.age", "Age", base.DEC)

amongus_protocol.fields = { 
    -- header
    send_option, send_option_name, 
    sequence, message_length, 
    opcode, opcode_name,
    -- payload
    disconnect_reason,
    client_version, 
    player_name,
    max_players,
    players,
    language,
    map,
    num_imposters,
    game_code,
    game_code_string,
    player_id,
    host_id,
    server_name,
    ip_address,
    port,
    age,
    -- alter game
    alter_game_type,
    alter_game_value
}

function amongus_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = amongus_protocol.name
  local subtree = tree:add(amongus_protocol, buffer(), "Among Us Protocol Data")

  -- every packet starts with a send option which determines how to dissect the rest of the packet
  local send_option_value = buffer(0,1):uint()
  subtree:add(send_option, buffer(0,1))
  local send_option_str = get_send_option_name(send_option_value)
  subtree:add(send_option_name, send_option_str)

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
    local name_length = buffer(8,1):uint()
    subtree:add(player_name, buffer(9,name_length))
    opcode_offset = -1
    data_offset = -1
  elseif send_option_value == 9 then -- Disconnect
    opcode_offset = -1
    data_offset = -1
  elseif send_option_value == 10 then -- Acknowledgement
    subtree:add(sequence, buffer(1,2))
    -- TODO: Decode last byte of Acknowledgement - likely part of Hazel netcode
    -- subtree:add(disconnect_reason, buffer(3,1))
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
    opcode_value = buffer(opcode_offset,1):uint()
    subtree:add(opcode, buffer(opcode_offset,1))
    opcode_name_str = get_opcode_name(opcode_value)
    subtree:add(opcode_name, opcode_name_str)
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

function dissect_hostgame(buffer, data_offset, pinfo, tree)
    length = buffer:len()
    if length == 10 then 
        local host_game_subtree = tree:add(amongus_protocol, buffer(), "Host Game Response")
        host_game_subtree:add_le(game_code, buffer(data_offset, 4))
        local game_code_value = buffer(data_offset,4):le_int()
        host_game_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))
    else  
      local host_game_subtree = tree:add(amongus_protocol, buffer(), "Host Game Request")
      host_game_subtree:add(max_players, buffer(data_offset+2, 1))
      host_game_subtree:add(language, buffer(data_offset+3, 2))
      host_game_subtree:add(map, buffer(data_offset+6, 1))
      host_game_subtree:add(num_imposters, buffer(data_offset+31, 1))

      -- TODO: Dissect remaining bytes of host game packet
    end
end

function dissect_joingame(buffer, data_offset, pinfo, tree)
    length = buffer:len()
    if length == 11 then 
        local join_game_subtree = tree:add(amongus_protocol, buffer(), "Join Game Request")
        join_game_subtree:add_le(game_code, buffer(data_offset, 4))
        local game_code_value = buffer(data_offset,4):le_int()
        join_game_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))

        -- TODO: Dissect last byte that always seems to be 0x07
    else
        local join_game_error_subtree = tree:add(amongus_protocol, buffer(), "Join Game Error")
        join_game_error_subtree:add(disconnect_reason, buffer(data_offset, 1))

        -- TODO: Map disconnect reasons to string values 'disconnect_reason_string' column
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

    -- TODO: Dissect Game Data
end

function dissect_gamedatato(buffer, data_offset, pinfo, tree)
    local game_data_to_subtree = tree:add(amongus_protocol, buffer(), "Game Data To")
    game_data_to_subtree:add_le(game_code, buffer(data_offset, 4))
    local game_code_value = buffer(data_offset,4):le_int()
    game_data_to_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))
    game_data_to_subtree:add(player_id, buffer(data_offset+4, 4))

    -- TODO: Dissect Game Data
end

function dissect_joinedgame(buffer, data_offset, pinfo, tree)
    local joined_game_subtree = tree:add(amongus_protocol, buffer(), "Joined Game Request")
    joined_game_subtree:add_le(game_code, buffer(data_offset, 4))
    local game_code_value = buffer(data_offset,4):le_int()
    joined_game_subtree:add(game_code_string, IntToGameCodeV2(game_code_value))
    joined_game_subtree:add(player_id, buffer(data_offset+4, 4))
    joined_game_subtree:add(host_id, buffer(data_offset+8, 4))
    joined_game_subtree:add(players, buffer(data_offset+12, 1))
    -- TODO: Parse packed player ids and update offset for decoding alter game

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
    kick_player_subtree:add(player_id, buffer(data_offset+4, 4))
    -- TODO: Parse packed player id
    -- TODO: Parse ban boolean in last byte
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
    length = buffer:len()
    if length == 50 then 
        local get_game_list_request_subtree = tree:add(amongus_protocol, buffer(), "Get Game List V2 Request")
        get_game_list_request_subtree:add(max_players, buffer(data_offset+3, 1))
        get_game_list_request_subtree:add_le(language, buffer(data_offset+4, 2))
        get_game_list_request_subtree:add(map, buffer(data_offset+8, 1))
        get_game_list_request_subtree:add(num_imposters, buffer(data_offset+32, 1))
        -- TODO: Dissect remaining bytes of get game list v2 packet
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
    a = bit32.band(code, 0x3FF)
    b = bit32.rshift(code,10) 
    b = bit32.band(b, 0xFFFFF)

    out1 = string.sub(gameCodeV2, 1 + math.floor(a%26), 1 + math.floor(a%26))
    out2 = string.sub(gameCodeV2, 1 + math.floor(a/26), 1 + math.floor(a/26))
    out3 = string.sub(gameCodeV2, 1 + math.floor(b%26), 1 + math.floor(b%26))
    out4 = string.sub(gameCodeV2, 1 + math.floor(b/26%26), 1 + math.floor(b/26%26))
    out5 = string.sub(gameCodeV2, 1 + math.floor(b/(26*26)%26), 1 + math.floor(b/(26*26)%26))
    out6 = string.sub(gameCodeV2, 1 + math.floor(b/(26*26*26)%26), 1 + math.floor(b/(26*26*26)%26))
    
    return out1 .. out2 .. out3 .. out4 .. out5 .. out6
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(22023, amongus_protocol)
udp_port:add(22623, amongus_protocol)