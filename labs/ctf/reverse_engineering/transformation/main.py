#with open('enc', 'r') as f:
#    flag = f.read()
#
##result =''.join([chr(str(flag[i]) << 8) + ord(str(flag[i + 1])) for i in range(0, len(flag), 2)])
#

#flag = "灩捯䍔䙻ㄶ形楴獟楮獴㌴摟潦弸弰摤捤㤷慽"
#
#''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])

flag = "灩捯䍔䙻ㄶ形楴獟楮獴㌴摟潦弸弰摤捤㤷慽"

decoded = ''.join([
    chr(ord(c) >> 8) + chr(ord(c) & 0xFF) for c in flag
])

print(decoded)
