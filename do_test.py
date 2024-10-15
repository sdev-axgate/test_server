import test_server_tools

def setting():
    tmp_cmd = "docker start ubun-snort2"
    test_server_tools.do_in_terminal(order=tmp_cmd)
    tmp_cmd = "docker start ubun-snort3"
    test_server_tools.do_in_terminal(order=tmp_cmd)
    tmp_cmd = "docker start suri6"
    test_server_tools.do_in_terminal(order=tmp_cmd)
    tmp_cmd = "docker start ubun-suri7"
    test_server_tools.do_in_terminal(order=tmp_cmd)

def snort2_0(output : dict, rule : str):
    normal_output = {}
    attack_output = {}

    prefix = "docker exec ubun-snort2 "

    # change local.rule & inject pcap files
    test_server_tools.change_rule_snort2(rule)
    test_server_tools.inject_pcap("ubun-snort2")

    # do normal_test
    order = prefix + "snort -c /etc/snort/snort.conf -r /prog/1.pcap -A console -q -v"
    result = test_server_tools.do_in_terminal(order=order)

    result = result.split("\n\n")[:-1]
    
    normal_alert_packet = []
    for i in range(0,len(result)):
        if result[i][23:27] == "[**]":
            normal_alert_packet.append(i+1)

    normal_alert_num = len(normal_alert_packet)
    normal_total_num = len(result)

    # do attack_test
    order = prefix + "snort -c /etc/snort/snort.conf -r /prog/2.pcap -A console -q -v"
    result = test_server_tools.do_in_terminal(order=order)
    result = result.split("\n\n")[:-1]
    
    attack_alert_packet = []
    for i in range(0,len(result)):
        if result[i][23:27] == "[**]":
            attack_alert_packet.append(i+1)

    attack_alert_num = len(attack_alert_packet)
    attack_total_num = len(result)

    # make output
    normal_output["총 패킷 수"] = normal_total_num
    normal_output["오탐된 패킷 수"] = normal_alert_num
    normal_output["오탐된 패킷"] = normal_alert_packet

    attack_output["총 패킷 수"] = attack_total_num
    attack_output["미탐된 패킷 수"] = attack_total_num - attack_alert_num
    attack_output["미탐된 패킷"] = test_server_tools.att_pack(attack_total_num, attack_alert_packet)

    output["정상 패킷 결과"] = normal_output
    output["공격 패킷 결과"] = attack_output

def snort2_1(output : dict, rule : str):
    time_list = [-1,-1,-1,-1, -1,-1,-1,-1]
    normal_cpu = []
    attack_cpu = []
    normal_memory = []
    attack_memory = []
    normal_output = {}
    attack_output = {}

    prefix = "docker exec ubun-snort2 "

    # change local.rule & inject pcap files
    test_server_tools.change_rule_snort2(" ")
    test_server_tools.inject_pcap("ubun-snort2")

    # do normal_test : time, performance
    order = prefix + "snort -c /etc/snort/snort.conf -r /prog/1.pcap -A console -q"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 0, num_2= 1)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test : time, performance
    order = prefix + "snort -c /etc/snort/snort.conf -r /prog/2.pcap -A console -q"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 4, num_2= 5)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # change local.rule & inject pcap files
    test_server_tools.change_rule_snort2(rule)

    # do normal_test
    order = prefix + "snort -c /etc/snort/snort.conf -r /prog/1.pcap -A console -q"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 2, num_2= 3)
    normal_total_num = test_server_tools.count_packets("./pcap_files/1.pcap")
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test
    order = prefix + "snort -c /etc/snort/snort.conf -r /prog/2.pcap -A console -q"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 6, num_2= 7)
    attack_total_num = test_server_tools.count_packets("./pcap_files/2.pcap")
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # make output
    normal_output["총 패킷 수"] = normal_total_num
    normal_output["평균 시간_룰 적용 전"] = time_list[1] - time_list[0]
    normal_output["평균 시간_룰 적용 후"] = time_list[3] - time_list[2]
    normal_output["평균 cpu_룰 적용 전"] = normal_cpu[0]
    normal_output["평균 cpu_룰 적용 후"] = normal_cpu[1]
    normal_output["평균 memory_룰 적용 전"] = normal_memory[0]
    normal_output["평균 memory_룰 적용 후"] = normal_memory[1]

    attack_output["총 패킷 수"] = attack_total_num
    attack_output["평균 시간_룰 적용 전"] = time_list[5] - time_list[4]
    attack_output["평균 시간_룰 적용 후"] = time_list[7] - time_list[6]
    attack_output["평균 cpu_룰 적용 전"] = attack_cpu[0]
    attack_output["평균 cpu_룰 적용 후"] = attack_cpu[1]
    attack_output["평균 memory_룰 적용 전"] = attack_memory[0]
    attack_output["평균 memory_룰 적용 후"] = attack_memory[1]

    output["정상 패킷 결과"] = normal_output
    output["공격 패킷 결과"] = attack_output

def snort2_2(output : dict, rule : str):
    time_list = [-1,-1,-1,-1, -1,-1,-1,-1]
    normal_cpu = []
    attack_cpu = []
    normal_memory = []
    attack_memory = []
    normal_output = {}
    attack_output = {}

    prefix = "docker exec ubun-snort2 "

    # change local.rule & inject pcap files
    test_server_tools.change_rule_snort2(" ")
    test_server_tools.inject_pcap("ubun-snort2")

    # do normal_test : time, performance
    order = prefix + "snort -c /etc/snort/snort.conf -r /prog/1.pcap -A console -q"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 0, num_2= 1)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test : time, performance
    order = prefix + "snort -c /etc/snort/snort.conf -r /prog/2.pcap -A console -q"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 4, num_2= 5)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # change local.rule & inject pcap files
    test_server_tools.change_rule_snort2(rule)

    # do normal_test
    order = prefix + "snort -c /etc/snort/snort.conf -r /prog/1.pcap -A console -q -v"
    result = test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 2, num_2= 3)
    result = result.split("\n\n")[:-1]
    
    normal_alert_packet = []
    for i in range(0,len(result)):
        if result[i][23:27] == "[**]":
            normal_alert_packet.append(i+1)

    normal_alert_num = len(normal_alert_packet)
    normal_total_num = len(result)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test
    order = prefix + "snort -c /etc/snort/snort.conf -r /prog/2.pcap -A console -q -v"
    result = test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 6, num_2= 7)
    result = result.split("\n\n")[:-1]
    
    attack_alert_packet = []
    for i in range(0,len(result)):
        if result[i][23:27] == "[**]":
            attack_alert_packet.append(i+1)

    attack_alert_num = len(attack_alert_packet)
    attack_total_num = len(result)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # make output
    normal_output["총 패킷 수"] = normal_total_num
    normal_output["오탐된 패킷 수"] = normal_alert_num
    normal_output["오탐된 패킷"] = normal_alert_packet
    normal_output["평균 시간_룰 적용 전"] = time_list[1] - time_list[0]
    normal_output["평균 시간_룰 적용 후"] = time_list[3] - time_list[2]
    normal_output["평균 cpu_룰 적용 전"] = normal_cpu[0]
    normal_output["평균 cpu_룰 적용 후"] = normal_cpu[1]
    normal_output["평균 memory_룰 적용 전"] = normal_memory[0]
    normal_output["평균 memory_룰 적용 후"] = normal_memory[1]

    attack_output["총 패킷 수"] = attack_total_num
    attack_output["미탐된 패킷 수"] = attack_total_num - attack_alert_num
    attack_output["미탐된 패킷"] = test_server_tools.att_pack(attack_total_num, attack_alert_packet)
    attack_output["평균 시간_룰 적용 전"] = time_list[5] - time_list[4]
    attack_output["평균 시간_룰 적용 후"] = time_list[7] - time_list[6]
    attack_output["평균 cpu_룰 적용 전"] = attack_cpu[0]
    attack_output["평균 cpu_룰 적용 후"] = attack_cpu[1]
    attack_output["평균 memory_룰 적용 전"] = attack_memory[0]
    attack_output["평균 memory_룰 적용 후"] = attack_memory[1]

    output["정상 패킷 결과"] = normal_output
    output["공격 패킷 결과"] = attack_output

### snort 3 ###

def snort3_0(output : dict, rule : str):
    normal_output = {}
    attack_output = {}

    prefix = "docker exec ubun-snort3 "

    # change local.rule & inject pcap files
    test_server_tools.change_rule_snort3(rule)
    test_server_tools.inject_pcap("ubun-snort3")

    # do normal_test
    order = prefix + "snort -R /prog/test.rules -r /prog/1.pcap -A alert_csv -q"
    result_1 = test_server_tools.do_in_terminal(order=order)

    # do attack_test
    order = prefix + "snort -R /prog/test.rules -r /prog/2.pcap -A alert_csv -q"
    result_2 = test_server_tools.do_in_terminal(order=order)

    # compute
    result_list_1 = result_1.split("\n")[:-1]

    packet_list_1 = []
    for i in result_list_1:
        ttmp = i.split()
        packet_list_1.append(ttmp[1][:-1])

    packet_list_1 = test_server_tools.str_to_int_list(packet_list_1)
    normal_alert_num = len(packet_list_1)
    normal_alert_packet = packet_list_1
    normal_total_num = test_server_tools.count_packets("./pcap_files/1.pcap")


    result_list_2 = result_2.split("\n")[:-1]

    packet_list_2 = []
    for i in result_list_2:
        ttmp = i.split()
        packet_list_2.append(ttmp[1][:-1])
    
    packet_list_2 = test_server_tools.str_to_int_list(packet_list_2)
    attack_alert_num = len(packet_list_2)
    attack_total_num = test_server_tools.count_packets("./pcap_files/2.pcap")
    attack_alert_packet = test_server_tools.att_pack(attack_total_num, packet_list_2)

    # make output
    normal_output["총 패킷 수"] = normal_total_num
    normal_output["오탐된 패킷 수"] = normal_alert_num
    normal_output["오탐된 패킷"] = normal_alert_packet

    attack_output["총 패킷 수"] = attack_total_num
    attack_output["미탐된 패킷 수"] = attack_total_num - attack_alert_num
    attack_output["미탐된 패킷"] = attack_alert_packet

    output["정상 패킷 결과"] = normal_output
    output["공격 패킷 결과"] = attack_output

def snort3_1(output : dict, rule : str):
    time_list = [-1,-1,-1,-1, -1,-1,-1,-1]
    normal_cpu = []
    attack_cpu = []
    normal_memory = []
    attack_memory = []
    normal_output = {}
    attack_output = {}

    prefix = "docker exec ubun-snort3 "

    # change local.rule & inject pcap files
    test_server_tools.change_rule_snort3(" ")
    test_server_tools.inject_pcap("ubun-snort3")

    # do normal_test : time, performance
    order = prefix + "snort -R /prog/test.rules -r /prog/1.pcap -A alert_csv -q"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 0, num_2= 1)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test : time, performance
    order = prefix + "snort -R /prog/test.rules -r /prog/2.pcap -A alert_csv -q"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 4, num_2= 5)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # change local.rule & inject pcap files
    test_server_tools.change_rule_snort3(rule)

    # do normal_test
    order = prefix + "snort -R /prog/test.rules -r /prog/1.pcap -A alert_csv -q"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 2, num_2= 3)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test
    order = prefix + "snort -R /prog/test.rules -r /prog/2.pcap -A alert_csv -q"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 6, num_2= 7)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    normal_total_num = test_server_tools.count_packets("./pcap_files/1.pcap")
    attack_total_num = test_server_tools.count_packets("./pcap_files/2.pcap")

    # make output
    normal_output["총 패킷 수"] = normal_total_num
    normal_output["평균 시간_룰 적용 전"] = time_list[1] - time_list[0]
    normal_output["평균 시간_룰 적용 후"] = time_list[3] - time_list[2]
    normal_output["평균 cpu_룰 적용 전"] = normal_cpu[0]
    normal_output["평균 cpu_룰 적용 후"] = normal_cpu[1]
    normal_output["평균 memory_룰 적용 전"] = normal_memory[0]
    normal_output["평균 memory_룰 적용 후"] = normal_memory[1]

    attack_output["총 패킷 수"] = attack_total_num
    attack_output["평균 시간_룰 적용 전"] = time_list[5] - time_list[4]
    attack_output["평균 시간_룰 적용 후"] = time_list[7] - time_list[6]
    attack_output["평균 cpu_룰 적용 전"] = attack_cpu[0]
    attack_output["평균 cpu_룰 적용 후"] = attack_cpu[1]
    attack_output["평균 memory_룰 적용 전"] = attack_memory[0]
    attack_output["평균 memory_룰 적용 후"] = attack_memory[1]

    output["정상 패킷 결과"] = normal_output
    output["공격 패킷 결과"] = attack_output

def snort3_2(output : dict, rule : str):
    time_list = [-1,-1,-1,-1, -1,-1,-1,-1]
    normal_cpu = []
    attack_cpu = []
    normal_memory = []
    attack_memory = []
    normal_output = {}
    attack_output = {}

    prefix = "docker exec ubun-snort3 "

    # change local.rule & inject pcap files
    test_server_tools.change_rule_snort3(" ")
    test_server_tools.inject_pcap("ubun-snort3")

    # do normal_test : time, performance
    order = prefix + "snort -R /prog/test.rules -r /prog/1.pcap -A alert_csv -q"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 0, num_2= 1)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test : time, performance
    order = prefix + "snort -R /prog/test.rules -r /prog/2.pcap -A alert_csv -q"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 4, num_2= 5)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # change local.rule & inject pcap files
    test_server_tools.change_rule_snort3(rule)

    # do normal_test
    order = prefix + "snort -R /prog/test.rules -r /prog/1.pcap -A alert_csv -q"
    result_1 = test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 2, num_2= 3)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test
    order = prefix + "snort -R /prog/test.rules -r /prog/2.pcap -A alert_csv -q"
    result_2 = test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 6, num_2= 7)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # compute
    result_list_1 = result_1.split("\n")[:-1]

    packet_list_1 = []
    for i in result_list_1:
        ttmp = i.split()
        packet_list_1.append(ttmp[1][:-1])

    normal_alert_num = len(packet_list_1)
    normal_alert_packet = test_server_tools.str_to_int_list(packet_list_1)
    normal_total_num = test_server_tools.count_packets("./pcap_files/1.pcap")


    result_list_2 = result_2.split("\n")[:-1]

    packet_list_2 = []
    for i in result_list_2:
        ttmp = i.split()
        packet_list_2.append(ttmp[1][:-1])
    
    packet_list_2 = test_server_tools.str_to_int_list(packet_list_2)
    attack_alert_num = len(packet_list_2)
    attack_total_num = test_server_tools.count_packets("./pcap_files/2.pcap")
    attack_alert_packet = test_server_tools.att_pack(attack_total_num, packet_list_2)
    
    
    # make output
    normal_output["총 패킷 수"] = normal_total_num
    normal_output["오탐된 패킷 수"] = normal_alert_num
    normal_output["오탐된 패킷"] = normal_alert_packet
    normal_output["평균 시간_룰 적용 전"] = time_list[1] - time_list[0]
    normal_output["평균 시간_룰 적용 후"] = time_list[3] - time_list[2]
    normal_output["평균 cpu_룰 적용 전"] = normal_cpu[0]
    normal_output["평균 cpu_룰 적용 후"] = normal_cpu[1]
    normal_output["평균 memory_룰 적용 전"] = normal_memory[0]
    normal_output["평균 memory_룰 적용 후"] = normal_memory[1]

    attack_output["총 패킷 수"] = attack_total_num
    attack_output["미탐된 패킷 수"] = attack_total_num - attack_alert_num
    attack_output["미탐된 패킷"] = attack_alert_packet
    attack_output["평균 시간_룰 적용 전"] = time_list[5] - time_list[4]
    attack_output["평균 시간_룰 적용 후"] = time_list[7] - time_list[6]
    attack_output["평균 cpu_룰 적용 전"] = attack_cpu[0]
    attack_output["평균 cpu_룰 적용 후"] = attack_cpu[1]
    attack_output["평균 memory_룰 적용 전"] = attack_memory[0]
    attack_output["평균 memory_룰 적용 후"] = attack_memory[1]

    output["정상 패킷 결과"] = normal_output
    output["공격 패킷 결과"] = attack_output

### suri 6 ###

def suri6_0(output : dict, rule : str):
    normal_output = {}
    attack_output = {}

    prefix = "docker exec suri6 "

    # change local.rule & inject pcap files
    test_server_tools.change_rule_suri6(rule)
    test_server_tools.inject_pcap("suri6")

    # clean log
    test_server_tools.clear_log_suri(prefix=prefix)

    # do normal_test
    order = prefix + "suricata -r /prog/1.pcap -l /prog/logs"
    test_server_tools.do_in_terminal(order=order)
    result_1 = test_server_tools.check_alert_suri()

    # clean log
    test_server_tools.clear_log_suri(prefix=prefix)

    # do attack_test
    order = prefix + "suricata -r /prog/2.pcap -l /prog/logs"
    test_server_tools.do_in_terminal(order=order)
    result_2 = test_server_tools.check_alert_suri()

    normal_alert_packet = result_1
    normal_alert_num = len(result_1)
    normal_total_num = test_server_tools.count_packets("./pcap_files/1.pcap")

    attack_alert_num = len(result_2)
    attack_total_num = test_server_tools.count_packets("./pcap_files/2.pcap")
    attack_alert_packet = test_server_tools.att_pack(attack_total_num, result_2)

    # make output
    normal_output["총 패킷 수"] = normal_total_num
    normal_output["오탐된 패킷 수"] = normal_alert_num
    normal_output["오탐된 패킷"] = normal_alert_packet

    attack_output["총 패킷 수"] = attack_total_num
    attack_output["미탐된 패킷 수"] = attack_total_num - attack_alert_num
    attack_output["미탐된 패킷"] = attack_alert_packet

    output["정상 패킷 결과"] = normal_output
    output["공격 패킷 결과"] = attack_output

def suri6_1(output : dict, rule : str):
    time_list = [-1,-1,-1,-1, -1,-1,-1,-1]
    normal_cpu = []
    attack_cpu = []
    normal_memory = []
    attack_memory = []
    normal_output = {}
    attack_output = {}

    prefix = "docker exec suri6 "

    # change local.rule & inject pcap files
    test_server_tools.change_rule_suri6(" ")
    test_server_tools.inject_pcap("suri6")

    # do normal_test : time, performance
    order = prefix + "suricata -r /prog/1.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 0, num_2= 1)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test : time, performance
    order = prefix + "suricata -r /prog/2.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 4, num_2= 5)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # change local.rule & inject pcap files
    test_server_tools.change_rule_suri6(rule)

    # do normal_test
    order = prefix + "suricata -r /prog/1.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 2, num_2= 3)
    normal_total_num = test_server_tools.count_packets("./pcap_files/1.pcap")
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test
    order = prefix + "suricata -r /prog/2.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 6, num_2= 7)
    attack_total_num = test_server_tools.count_packets("./pcap_files/2.pcap")
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # make output
    normal_output["총 패킷 수"] = normal_total_num
    normal_output["평균 시간_룰 적용 전"] = time_list[1] - time_list[0]
    normal_output["평균 시간_룰 적용 후"] = time_list[3] - time_list[2]
    normal_output["평균 cpu_룰 적용 전"] = normal_cpu[0]
    normal_output["평균 cpu_룰 적용 후"] = normal_cpu[1]
    normal_output["평균 memory_룰 적용 전"] = normal_memory[0]
    normal_output["평균 memory_룰 적용 후"] = normal_memory[1]

    attack_output["총 패킷 수"] = attack_total_num
    attack_output["평균 시간_룰 적용 전"] = time_list[5] - time_list[4]
    attack_output["평균 시간_룰 적용 후"] = time_list[7] - time_list[6]
    attack_output["평균 cpu_룰 적용 전"] = attack_cpu[0]
    attack_output["평균 cpu_룰 적용 후"] = attack_cpu[1]
    attack_output["평균 memory_룰 적용 전"] = attack_memory[0]
    attack_output["평균 memory_룰 적용 후"] = attack_memory[1]

    output["정상 패킷 결과"] = normal_output
    output["공격 패킷 결과"] = attack_output

def suri6_2(output : dict, rule : str):
    time_list = [-1,-1,-1,-1, -1,-1,-1,-1]
    normal_cpu = []
    attack_cpu = []
    normal_memory = []
    attack_memory = []
    normal_output = {}
    attack_output = {}

    prefix = "docker exec suri6 "

    # change local.rule & inject pcap files
    test_server_tools.change_rule_suri6(" ")
    test_server_tools.inject_pcap("suri6")

    # do normal_test : time, performance
    order = prefix + "suricata -r /prog/1.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 0, num_2= 1)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test : time, performance
    order = prefix + "suricata -r /prog/2.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 4, num_2= 5)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # change local.rule & inject pcap files
    test_server_tools.change_rule_suri6(rule)

    # clean log
    test_server_tools.clear_log_suri(prefix=prefix)

    # do normal_test
    order = prefix + "suricata -r /prog/1.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 2, num_2= 3)
    result = test_server_tools.check_alert_suri()
    
    normal_alert_num = len(result)
    normal_total_num = test_server_tools.count_packets("./pcap_files/1.pcap")
    normal_alert_packet = result
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # clean log
    test_server_tools.clear_log_suri(prefix=prefix)

    # do attack_test
    order = prefix + "suricata -r /prog/2.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 6, num_2= 7)
    result = test_server_tools.check_alert_suri()

    attack_alert_num = len(result)
    attack_total_num = test_server_tools.count_packets("./pcap_files/2.pcap")
    attack_alert_packet = test_server_tools.att_pack(attack_total_num, result)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # make output
    normal_output["총 패킷 수"] = normal_total_num
    normal_output["오탐된 패킷 수"] = normal_alert_num
    normal_output["오탐된 패킷"] = normal_alert_packet
    normal_output["평균 시간_룰 적용 전"] = time_list[1] - time_list[0]
    normal_output["평균 시간_룰 적용 후"] = time_list[3] - time_list[2]
    normal_output["평균 cpu_룰 적용 전"] = normal_cpu[0]
    normal_output["평균 cpu_룰 적용 후"] = normal_cpu[1]
    normal_output["평균 memory_룰 적용 전"] = normal_memory[0]
    normal_output["평균 memory_룰 적용 후"] = normal_memory[1]

    attack_output["총 패킷 수"] = attack_total_num
    attack_output["미탐된 패킷 수"] = attack_total_num - attack_alert_num
    attack_output["미탐된 패킷"] = attack_alert_packet
    attack_output["평균 시간_룰 적용 전"] = time_list[5] - time_list[4]
    attack_output["평균 시간_룰 적용 후"] = time_list[7] - time_list[6]
    attack_output["평균 cpu_룰 적용 전"] = attack_cpu[0]
    attack_output["평균 cpu_룰 적용 후"] = attack_cpu[1]
    attack_output["평균 memory_룰 적용 전"] = attack_memory[0]
    attack_output["평균 memory_룰 적용 후"] = attack_memory[1]

    output["정상 패킷 결과"] = normal_output
    output["공격 패킷 결과"] = attack_output



### suri 7 ###

def suri7_0(output : dict, rule : str):
    normal_output = {}
    attack_output = {}

    prefix = "docker exec ubun-suri7 "

    # change local.rule & inject pcap files
    test_server_tools.change_rule_suri7(rule)
    test_server_tools.inject_pcap("ubun-suri7")

    # clean log
    test_server_tools.clear_log_suri(prefix=prefix)

    # do normal_test
    order = prefix + "suricata -r /prog/1.pcap -l /prog/logs"
    test_server_tools.do_in_terminal(order=order)
    result = test_server_tools.check_alert_suri7()

    normal_alert_packet = result
    normal_alert_num = len(result)
    normal_total_num = test_server_tools.count_packets("./pcap_files/1.pcap")

    # clean log
    test_server_tools.clear_log_suri(prefix=prefix)

    # do attack_test
    order = prefix + "suricata -r /prog/2.pcap -l /prog/logs"
    test_server_tools.do_in_terminal(order=order)
    result = test_server_tools.check_alert_suri7()

    attack_alert_packet = result
    attack_alert_num = len(result)
    attack_total_num = test_server_tools.count_packets("./pcap_files/2.pcap")

    # make output
    normal_output["총 패킷 수"] = normal_total_num
    normal_output["오탐된 패킷 수"] = normal_alert_num
    normal_output["오탐된 패킷"] = normal_alert_packet

    attack_output["총 패킷 수"] = attack_total_num
    attack_output["미탐된 패킷 수"] = attack_total_num - attack_alert_num
    attack_output["미탐된 패킷"] = attack_alert_packet

    output["정상 패킷 결과"] = normal_output
    output["공격 패킷 결과"] = attack_output

def suri7_1(output : dict, rule : str):
    time_list = [-1,-1,-1,-1, -1,-1,-1,-1]
    normal_cpu = []
    attack_cpu = []
    normal_memory = []
    attack_memory = []
    normal_output = {}
    attack_output = {}

    prefix = "docker exec ubun-suri7 "

    # change local.rule & inject pcap files
    test_server_tools.change_rule_suri7(" ")
    test_server_tools.inject_pcap("ubun-suri7")

    # do normal_test : time, performance
    order = prefix + "suricata -r /prog/1.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 0, num_2= 1)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test : time, performance
    order = prefix + "suricata -r /prog/2.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 4, num_2= 5)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # change local.rule & inject pcap files
    test_server_tools.change_rule_suri7(rule)

    # do normal_test
    order = prefix + "suricata -r /prog/1.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 2, num_2= 3)
    normal_total_num = test_server_tools.count_packets("./pcap_files/1.pcap")
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test
    order = prefix + "suricata -r /prog/2.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 6, num_2= 7)
    attack_total_num = test_server_tools.count_packets("./pcap_files/2.pcap")
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # make output
    normal_output["총 패킷 수"] = normal_total_num
    normal_output["평균 시간_룰 적용 전"] = time_list[1] - time_list[0]
    normal_output["평균 시간_룰 적용 후"] = time_list[3] - time_list[2]
    normal_output["평균 cpu_룰 적용 전"] = normal_cpu[0]
    normal_output["평균 cpu_룰 적용 후"] = normal_cpu[1]
    normal_output["평균 memory_룰 적용 전"] = normal_memory[0]
    normal_output["평균 memory_룰 적용 후"] = normal_memory[1]

    attack_output["총 패킷 수"] = attack_total_num
    attack_output["평균 시간_룰 적용 전"] = time_list[5] - time_list[4]
    attack_output["평균 시간_룰 적용 후"] = time_list[7] - time_list[6]
    attack_output["평균 cpu_룰 적용 전"] = attack_cpu[0]
    attack_output["평균 cpu_룰 적용 후"] = attack_cpu[1]
    attack_output["평균 memory_룰 적용 전"] = attack_memory[0]
    attack_output["평균 memory_룰 적용 후"] = attack_memory[1]

    output["정상 패킷 결과"] = normal_output
    output["공격 패킷 결과"] = attack_output

def suri7_2(output : dict, rule : str):
    time_list = [-1,-1,-1,-1, -1,-1,-1,-1]
    normal_cpu = []
    attack_cpu = []
    normal_memory = []
    attack_memory = []
    normal_output = {}
    attack_output = {}

    prefix = "docker exec ubun-suri7 "

    # change local.rule & inject pcap files
    test_server_tools.change_rule_suri7(" ")
    test_server_tools.inject_pcap("ubun-suri7")

    # do normal_test : time, performance
    order = prefix + "suricata -r /prog/1.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 0, num_2= 1)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # do attack_test : time, performance
    order = prefix + "suricata -r /prog/2.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 4, num_2= 5)
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # change local.rule & inject pcap files
    test_server_tools.change_rule_suri7(rule)

    # clean log
    test_server_tools.clear_log_suri(prefix=prefix)

    # do normal_test
    order = prefix + "suricata -r /prog/1.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 2, num_2= 3)
    result = test_server_tools.check_alert_suri7()
    
    normal_alert_num = len(result)
    normal_alert_packet = result
    normal_total_num = test_server_tools.count_packets("./pcap_files/1.pcap")
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=normal_cpu, memory_list=normal_memory)

    # clean log
    test_server_tools.clear_log_suri(prefix=prefix)

    # do attack_test
    order = prefix + "suricata -r /prog/2.pcap -l /prog/logs"
    test_server_tools.do_in_terminal_time(order=order, time_list=time_list, num_1= 6, num_2= 7)
    result = test_server_tools.check_alert_suri7()

    attack_alert_num = len(result)
    attack_alert_packet = result
    attack_total_num = test_server_tools.count_packets("./pcap_files/2.pcap")
    test_server_tools.do_in_terminal_perf(order=order, cpu_list=attack_cpu, memory_list=attack_memory)

    # make output
    normal_output["총 패킷 수"] = normal_total_num
    normal_output["오탐된 패킷 수"] = normal_alert_num
    normal_output["오탐된 패킷"] = normal_alert_packet
    normal_output["평균 시간_룰 적용 전"] = time_list[1] - time_list[0]
    normal_output["평균 시간_룰 적용 후"] = time_list[3] - time_list[2]
    normal_output["평균 cpu_룰 적용 전"] = normal_cpu[0]
    normal_output["평균 cpu_룰 적용 후"] = normal_cpu[1]
    normal_output["평균 memory_룰 적용 전"] = normal_memory[0]
    normal_output["평균 memory_룰 적용 후"] = normal_memory[1]

    attack_output["총 패킷 수"] = attack_total_num
    attack_output["미탐된 패킷 수"] = attack_total_num - attack_alert_num
    attack_output["미탐된 패킷"] = attack_alert_packet
    attack_output["평균 시간_룰 적용 전"] = time_list[5] - time_list[4]
    attack_output["평균 시간_룰 적용 후"] = time_list[7] - time_list[6]
    attack_output["평균 cpu_룰 적용 전"] = attack_cpu[0]
    attack_output["평균 cpu_룰 적용 후"] = attack_cpu[1]
    attack_output["평균 memory_룰 적용 전"] = attack_memory[0]
    attack_output["평균 memory_룰 적용 후"] = attack_memory[1]

    output["정상 패킷 결과"] = normal_output
    output["공격 패킷 결과"] = attack_output






