import regex as re
import pandas as pd

# Leer archivo .log
#se puede refactorizar

def parse_log(path):
    try:
        with open(path,"r", encoding="utf-8",errors="ignore") as f:
            data = f.read() #leer el contenido del archivo
    except FileNotFoundError:
        print("File not found.") # en caso de que no lo encuentre
        return pd.DataFrame()

    list_dataframe = []


    # Expresiones regulares para extraer información

    for line in data.splitlines(): # splitlines() para dividir el texto por lo saltos de linea
        #con cada iteracion del blucle hay que resetear las variables 
        #para que no queden rastros de la iteracion anterior
        
        fecha_hora = None
        ip_des = None
        message_type = None
        user = None
        ip_origin = None
        port = None
        service = None
        pid = None
        uid = None
        gid = None
        group_name = None
        command = None

        #busca esa expresion regular  indicada por cada renglon
        
        
        #fecha y hora
        fecha_hora = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
        if fecha_hora:# para no retornar un objeto al dataframe sino un string
            fecha_hora = fecha_hora.group(1)
    

        #ip hostname
        ip_des = re.search(r'(\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3})',line)
        if ip_des:
            ip_des = ip_des.group(1) 



        # ssh
        if  re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\s+sshd\[\d+\]',line) :

            #usuario 
            # ahi esta diceindo que busque por for (opcional el inavlid user ) una cadena + from
            user = re.search(r'for\s+(?:invalid\s+user\s+)?(\w+)\s+from|Invalid\s+user\s+(\w+)\s+from|user\s+(\w+)',line)

            ip_origin = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',line)
            if ip_origin:
                ip_origin = ip_origin.group(1)
            
            #Tipo de mensaje
            message_type = re.search(r'(Accepted password|Failed password for invalid user|Failed password|Invalid user| Disconnected from authenticating user|Received disconnect|PAM 1 more authentication failure)', line) 
            if message_type:
                message_type = message_type.group(1)
            #Puerto
            port = re.search(r'port\s+(\d+)',line) # con ( ) seleccionamos lo que queremos traer
            if port: # quitamos que se extraiga el objeto
                port = port.group(1) #  de esta forma quitamos los [] del puerto
            
        #cron 
        elif re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\s+CRON',line):
            user = re.search(r'for user (\w+)',line)     

            message_type = re.search(r'\s+(\w+\s+\w+)\s+for', line) 
            message_type = message_type.group(1)
        #useradd
        elif re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\s+useradd',line):
            #user
            user = re.search(r'user:\s+name=(\w+),',line) 
            #message_type
            message_type = re.search(r':\s+(\w+\s+\w+):', line) 
            message_type = message_type.group(1)
            #uid
            uid = re.search(r'UID=(\d+)',line)
            uid=uid.group(1)
            #gid
            gid = re.search(r'GID=(\d+)',line)
            gid=gid.group(1)
        #usermod
        elif re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\s+usermod',line):
            user = re.search(r"add\s+'(\w+)'",line)
            message_type =re.search(r'to\s+(\w+\s*\w*)',line) 
            message_type= message_type.group(1)
            group_name = re.search(r"group\s+'(\w+)'",line)
            group_name = group_name.group(1)
        #sudo
        elif re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\s+sudo',line):
            user = re.search(r'sudo:\s+(\w+)\s+:|by\s+(\w+)\(',line)
            command = re.search(r'COMMAND=/usr/bin/(.+)',line)
            if command:
                command = command.group(1)
            message_type = re.search(r'session opened for user root|session closed for user root',line)
            if message_type:
                message_type= message_type.group(0)

        if user:
            user = user.group(1) or user.group(2) or user.group(3) 


        
        #Servicio
        service = re.search(r'(sshd|sudo|CRON|useradd|usermod)',line)
        if service:
            service = service.group(1)

        
        #PID (numero de proceso asignado por el sistema)
        pid = re.search(r'\w+\[(\d+)\]',line)
        if pid:
            pid = pid.group(1)

        dic_dataframe = {
            'service': service,
            'fecha_hora':fecha_hora,
            'host':ip_des,
            'message_type':message_type,
            'user':user,
            'UID':uid,
            'GID':gid,
            'ip_origin': ip_origin,
            'port': port,
            'pid': pid,
            'group_name':group_name,
            'command':command
        }
        list_dataframe.append(dic_dataframe)

    df = pd.DataFrame(list_dataframe)
    # por defecto pandas agrega el año 1900 si no hay año
    df['fecha_hora'] = pd.to_datetime(df['fecha_hora'], format='%b %d %H:%M:%S') # Se agrego para que el formado de la fehca y hora sea en datatime
    df.reset_index()
    return df 
