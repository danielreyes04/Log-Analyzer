import regex as re
import pandas as pd

# Leer archivo .log

#path = "data/raw/auth.log" # ruta para pruebas

def parse_log(path):
    try:
        with open(path,"r", encoding="utf-8",errors="ignore") as f:
            data = f.read() #leer el contenido del archivo
    except FileNotFoundError:
        print("File not found.") # en caso de que no lo encuentre


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

        #busca esa expresion regular  indicada por cada renglon
        
        
        #fecha y hora
        fecha_hora = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
        if fecha_hora:# para no retornar un objeto al dataframe sino un string
            fecha_hora = fecha_hora.group(1)
    

        #ip hostname
        ip_des = re.search(r'(\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3})',line)
        if ip_des:
            ip_des = ip_des.group(1) 


        #Tipo de mensaje
        message_type = re.search(r'(Accepted password|Failed password for invalid user|Failed password|Connection closed|Received disconnect|Disconnected from user|session opened|session closed|Disconnected|Invalid user)', line) 
        if message_type:
            message_type = message_type.group(1)


        #usuario
        if  re.search(r'ssh',line) :
            # ahi esta diceindo que busque por for (opcional el inavlid user ) una cadena + from
            user = re.search(r'for\s+(?:invalid\s+user\s+)?(\w+)\s+from',line)
        else:
            #de momento funciona para cron pero habria que implemtar una funcionalidad en si para el
            user = re.search(r'user\s+(\w+)',line)
        
        if user:
            user = user.group(1)


        #ip origen
        ip_origin = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',line)
        if ip_origin:
            ip_origin = ip_origin.group(1)
        

        #Puerto
        port = re.search(r'port\s+(\d+)',line) # con ( ) seleccionamos lo que queremos traer
        if port: # quitamos que se extraiga el objeto
            port = port.group(1) #  de esta forma quitamos los [] del puerto
        
        #Servicio
        service = re.search(r'(sshd|sudo|CRON)',line)
        if service:
            service = service.group(1)

        
        #PID (numero de proceso asignado por el sistema)
        pid = re.search(r'\w+\[(\d+)\]',line)
        if pid:
            pid = pid.group(1)

        dic_dataframe = {
            'fecha_hora':fecha_hora,
            'host':ip_des,
            'message_type':message_type,
            'user':user,
            'service': service,
            'ip_origin': ip_origin,
            'port': port,
            'pid': pid
        }
        list_dataframe.append(dic_dataframe)

    df = pd.DataFrame(list_dataframe)
    df.reset_index()
    return df 
