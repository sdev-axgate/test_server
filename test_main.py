from fastapi import FastAPI, File, UploadFile, Form
from typing import List
import uvicorn
import asyncio

import do_test

app = FastAPI()

@app.on_event("startup")
def startup_event():
    do_test.setting()

@app.get("/")
def reed_root():
    return {"Test" : "World"}

@app.post("/test")
async def test(
    rule: str = Form(...), 
    envi: int = Form(...),
    what_test: int = Form(...),
    files: List[UploadFile] = File(...)
    ):

    # print("check test server - begin")

    # file_list = []
    file_index = 1
    for file in files:
        # 파일 처리 (예: 파일 이름 반환)
        file_content = await file.read()
        # file_info = {"filename": file.filename, "content": file_content.decode("utf-8")}

        # file_list.append(file_info)

        # 파일 저장하기
        tmp_name = str(file_index) + ".pcap"
        fd = open("./pcap_files/"+tmp_name, "wb")
        fd.write(file_content)
        fd.close()

        file_index += 1

    

    # make output
    output = {}

    # set envi, what_test
    func_list = []
    tmp_snort2 = [do_test.snort2_0, do_test.snort2_1, do_test.snort2_2]
    tmp_snort3 = [do_test.snort3_0, do_test.snort3_1, do_test.snort3_2]
    tmp_suri6 = [do_test.suri6_0, do_test.suri6_1, do_test.suri6_2]
    tmp_suri7 = [do_test.suri7_0, do_test.suri7_1, do_test.suri7_2]
    func_list.append(tmp_snort2)
    func_list.append(tmp_snort3)
    func_list.append(tmp_suri6)
    func_list.append(tmp_suri7)
    
    # do test
    func_list[envi][what_test](output, rule)
    
    # print(output)

    return output
    
    
    # print("check test server - end")
    
    # JSON 데이터와 파일 정보를 함께 반환
    # return {"data": {"rule": rule, "envi": envi, "what_test": what_test}, "file_list": file_list}


@app.get("/change_server_url")
def insert_server():

    return {"message" : "inserted"}

# FastAPI 서버 실행
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8008)



