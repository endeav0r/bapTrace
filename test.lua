local lbaptrace = require('lbapTrace')

local crash_0 = lbaptrace.open('crash_0.bpt')

while crash_0:end_of_trace() == false do
    local frame = crash_0:get_frame()


    if frame.type == 'modload_frame' then
        print(frame.type .. '  [' ..
              string.format('%08x', frame.low_address) .. ' .. ' ..
              string.format('%08x', frame.high_address) .. ']   ' ..
              frame.module_name)


    elseif frame.type == 'std_frame' then
        print(frame.type .. '  [' .. tostring(frame.thread_id) .. ' ' ..
              string.format('%08x', frame.address) .. ']  ')
        for k,op in pairs(frame.operand_pre_list) do
            local opstr = '  ['
            
            if op.read    then opstr = opstr .. 'r' else opstr = opstr .. ' ' end
            if op.written then opstr = opstr .. 'w' else opstr = opstr .. ' ' end
            if op.index   then opstr = opstr .. 'i' else opstr = opstr .. ' ' end
            if op.base    then opstr = opstr .. 'b' else opstr = opstr .. ' ' end
            
            opstr = opstr .. ']  ' .. string.format('%02d', op.bit_length) .. '  '
            
            if op.type == 'mem' then
                opstr = opstr .. 'mem=' .. string.format('%08x', op.address) .. '  '
            else
                opstr = opstr .. 'reg=' .. string.format('%-08s', op.name) .. '  '
            end

            if op.taint == 'multiple' then
                opstr = opstr .. 'taint=multiple'
            elseif op.taint ~= nil then
                opstr = opstr .. 'taint=' .. tostring(op.taint)
            end

            print(opstr)
        end


    elseif frame.type == 'taint_intro_frame' then
        for k,taint_intro in pairs(frame.taint_intro_list) do
            local taintstr = '  taint_intro ' .. string.format('%04x', taint_intro.taint_id) .. '  [' ..
                             string.format('%08x', taint_intro.address) .. ']  '
            if taint_intro.offset ~= nil then
                taintstr = taintstr .. 'offset=' .. string.format('%04x', taint_intro.offset) .. '  '
            end

            if taint_intro.source_name ~= nil then
                taintstr = taintstr .. taint_intro.source_name
            end

            print(taintstr)
        end
    end
end