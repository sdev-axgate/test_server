import subprocess
import time
import multiprocessing
import psutil
import json

def do_in_terminal(order : str):
    # order = "snort -A console -c /etc/snort/snort.conf -r ./CVE-2021-44228.pcap -q"
    command = "sudo " + order
    password = "isy123"

    process = subprocess.Popen(['sudo', '-S'] + command.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate(password.encode() + b'\n')

    # print(output.decode())
    # print("error :", error.decode())
    return(output.decode())

def do_in_terminal_time(order : str, time_list : list, num_1 : int, num_2 : int):
    # order = "snort -A console -c /etc/snort/snort.conf -r ./CVE-2021-44228.pcap -q"
    command = "sudo " + order
    password = "isy123"

    time_list[num_1] = time.time()
    process = subprocess.Popen(['sudo', '-S'] + command.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate(password.encode() + b'\n')
    time_list[num_2] = time.time()

    # print(output.decode())
    # print("error :", error.decode())
    return(output.decode())

def perf_func_1(command, password):
    time.sleep(1)
    process = subprocess.Popen(['sudo', '-S'] + command.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate(password.encode() + b'\n')

def perf_func_2(results, event):
    # print("func_2 시작")
    time.sleep(1)
    while not event.is_set():
        # 시스템 메모리 및 CPU 사용량 기록
        memory_info = psutil.virtual_memory()
        memory_usage_mb = memory_info.used / (1024 ** 2)  # 메모리 사용량을 MB로 변환
        cpu_usage = psutil.cpu_percent(interval=0.1)
        results.append((cpu_usage, memory_usage_mb))  # 리스트에 (CPU, 메모리) 튜플로 저장
    # print("func_2 종료")

def do_in_terminal_perf(order : str, cpu_list : list, memory_list : list):
    command = "sudo " + order
    password = "isy123"

    # do in multi_process
    event = multiprocessing.Event()

    with multiprocessing.Manager() as manager:
        results = manager.list()  # 공유 리스트 생성

        # 프로세스 생성
        p1 = multiprocessing.Process(target=perf_func_1, args=(command, password))
        p2 = multiprocessing.Process(target=perf_func_2, args=(results, event))

        # 프로세스 시작
        p1.start()
        p2.start()

        # func_1의 종료를 기다림
        p1.join()

        # func_1이 종료되었음을 알림
        event.set()

        # func_2의 종료를 기다림
        p2.join()

        # 결과 출력
        cpu_sum = 0
        memory_sum = 0
        num = len(results)

        for cpu, memory in results:
            cpu_sum += cpu
            memory_sum += memory
        
        cpu_avg = cpu_sum / num
        memory_avg = memory_sum / num

        cpu_list.append(cpu_avg)
        memory_list.append(memory_avg)

def change_rule(order : str):
    tmp_fd2 = open("local.rules", "w")
    body = order + "\n"
    tmp_fd2.write(body)
    tmp_fd2.close()

def inject_pcap(con_name : str):
    tmp_cmd = "docker cp ./pcap_files/1.pcap " + con_name + ":/prog"
    do_in_terminal(tmp_cmd)

    tmp_cmd = "docker cp ./pcap_files/2.pcap " + con_name + ":/prog"
    do_in_terminal(tmp_cmd)

def change_rule_snort2(order : str):
    tmp_fd2 = open("local.rules", "w")
    body = order + "\n"
    tmp_fd2.write(body)
    tmp_fd2.close()

    tmp_cmd = "docker cp ./local.rules ubun-snort2:/etc/snort/rules"
    do_in_terminal(tmp_cmd)

# def change_rule_snort3(order : str):
#     tmp_fd2 = open("test.rules", "w")
#     body = order + "\n"
#     tmp_fd2.write(body)
#     tmp_fd2.close()

#     tmp_cmd = "docker cp ./test.rules ubun-snort3:/etc/snort/rules"
#     do_in_terminal(tmp_cmd)     

def change_rule_snort3(order : str):
    tmp_fd2 = open("test.rules", "w")
    body = order + "\n"
    tmp_fd2.write(body)
    tmp_fd2.close()

    tmp_cmd = "docker cp ./test.rules ubun-snort3:/prog"
    do_in_terminal(tmp_cmd)

def change_rule_suri6(order : str):
    tmp_fd2 = open("suricata.rules", "w")
    body = order + "\n"
    tmp_fd2.write(body)
    tmp_fd2.close()

    tmp_cmd = "docker cp ./suricata.rules suri6:/etc/suricata/rules"
    do_in_terminal(tmp_cmd)

def change_rule_suri7(order : str):
    tmp_fd2 = open("suricata.rules", "w")
    body = order + "\n"
    tmp_fd2.write(body)
    tmp_fd2.close()

    tmp_cmd = "docker cp ./suricata.rules ubun-suri7:/etc/suricata/rules"
    do_in_terminal(tmp_cmd)

    # tmp_cmd = "docker cp ./pcap_files/1.pcap ubun-suri7:/prog"
    # do_in_terminal(tmp_cmd)

    # tmp_cmd = "docker cp ./pcap_files/2.pcap ubun-suri7:/prog"
    # do_in_terminal(tmp_cmd)

def clear_log_suri(prefix : str):
    order = prefix + "rm -r /prog/logs"
    do_in_terminal(order=order)
    order = prefix + "mkdir /prog/logs"
    do_in_terminal(order=order)

def check_alert_suri():
    order = '''docker cp suri6:/prog/logs/eve.json ./eve.json'''
    do_in_terminal(order=order)

    fd = open("eve.json", 'r')
    text = fd.read()
    fd.close()

    text = text.split("\n")
    text = text[:-1]

    dict_list = []
    for i in text:
        tmp_dict = json.loads(i)
        dict_list.append(tmp_dict)

    list_2 = []
    for i in dict_list:
        if i["event_type"] == "alert":
            list_2.append(i)

    list_3 = []
    for i in list_2:
        tmp_list = []
        tmp_list.append(i["pcap_cnt"])
        tmp_list.append(i["flow"]["pkts_toclient"])
        list_3.append(tmp_list[0] - tmp_list[1])

    list_3.sort()

    return list_3

def check_alert_suri7():
    order = '''docker cp ubun-suri7:/prog/logs/eve.json ./eve.json'''
    do_in_terminal(order=order)

    fd = open("eve.json", 'r')
    text = fd.read()
    fd.close()

    text = text.split("\n")
    text = text[:-1]

    dict_list = []
    for i in text:
        tmp_dict = json.loads(i)
        dict_list.append(tmp_dict)

    list_2 = []
    for i in dict_list:
        if i["event_type"] == "alert":
            list_2.append(i)

    list_3 = []
    for i in list_2:
        tmp_list = []
        tmp_list.append(i["pcap_cnt"])
        tmp_list.append(i["flow"]["pkts_toclient"])
        list_3.append(tmp_list[0] - tmp_list[1])

    list_3.sort()

    return list_3

def count_packets(pcap_file):
    # tcpdump 명령을 구성합니다.
    command = ['tcpdump', '-r', pcap_file]

    # subprocess.run()을 사용하여 명령을 실행하고 결과를 파이프를 통해 가져옵니다.
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # wc -l을 사용하여 패킷 수를 셉니다.
        packet_count = len(result.stdout.splitlines())

        return packet_count
    except Exception as e:
        print(f"오류 발생: {e}")
        return -1
    
def att_pack(total_num : int, pack_list : list):
    tmp_result_list = []

    for i in range(1,total_num+1):
        if i in pack_list:
            continue
        else:
            tmp_result_list.append(i)

    return tmp_result_list

def str_to_int_list(input_list : list):
    result = []

    for i in input_list:
        result.append(int(i))

    return result