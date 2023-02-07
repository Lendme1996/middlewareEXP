import getopt
import socket
import sys


# 启始函数
def start(argv):
    url = ""
    port = ""
    if len(sys.argv) < 2:
        print("-h 帮助信息; \n")
        sys.exit()
    # 异常捕获
    try:
        banner()
        opts, args = getopt.getopt(argv, "-u:-p:-h")
    except getopt.GetoptError:
        print("值输入有误")
        sys.exit()
    for opt, arg in opts:
        if opt == "-u":
            url = arg
        elif opt == "-p":
            port = arg
        elif opt == "-h":
            print(usage())
    launcher(url, port)


def launcher(url, port):
    # 未授权访问类型
    output = redis_unauthorized(url, port)
    output_result(output)


# redis未授权检测
def redis_unauthorized(url, port):
    result = []
    s = socket.socket()
    # 十六进制payload
    payload = "\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a"
    socket.setdefaulttimeout(10)
    try:
        s.connect((url, int(port)))
        s.sendall(payload.encode())
        recvdata = s.recv(1024).decode()
        # 检测返回值中是否有redis版本信息字段，如果有则存在未授权漏洞
        if "redis_version" in recvdata:
            result.append(str(url) + ':' + str(port) + ':' + 'succeed')
    except:
        pass
        result.append(str(url) + ':' + str(port) + ':' + 'failed')
        s.close()
    return result


# 个性化banner设置
def banner():
    print("""
  _____          _ _     _    _          _____                 
 |  __ \        | (_)   | |  | |  /\    / ____|                
 | |__) |___  __| |_ ___| |  | | /  \  | (___   ___ __ _ _ __  
 |  _  // _ \/ _` | / __| |  | |/ /\ \  \___ \ / __/ _` | '_ \ 
 | | \ \  __/ (_| | \__ \ |__| / ____ \ ____) | (_| (_| | | | |
 |_|  \_\___|\__,_|_|___/\____/_/    \_\_____/ \___\__,_|_| |_|                            
""")

# 帮助详情
def usage():
    print("-h: --hlep 查看帮助;")
    print("-p: --port 设置端口;")
    print("-u: --url  设置域名;")
    sys.exit()


# 输出函数
def output_result(output):
    print(output)
    print("++++++++++++++++++++++++++++++++++++++++++++++++")
    print("|         ip         |    port   |     status  |")
    for li in output:
        print("+-----------------+-----------+--------------+")
        print("|   " + li.replace(":", "   |    ") + "  | ")
    print("+----------------+------------+---------------+\n")


if __name__ == '__main__':
    try:
        start(sys.argv[1:])
    except KeyboardInterrupt:
        print("用户中断了程序，关闭所有执行线程")
