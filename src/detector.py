from parser import parse_log
import pandas as pd

path = "data/raw/auth.log"
df = parse_log(path)

# funcion para detectar posibles ataques de fuerza bruta
def brute_force(df, umbral = 5):
    
    ip_suspicious = [] #ip_suspicius es un lista de tuplas que va contener ip sospechosas >= al umbral
    list_dataframe=[] # lista para concatenar diferens dataframe por ip

    #filtramos el tipo de mensaje por intentos fallidos para ver si una ip lo repite muchas veces en muy poco tiempo
    fails = df[(df['tipo_mensaje'] == 'Failed password')|(df['tipo_mensaje'] ==  'Failed password for invalid user')]
    #con el groupby contamos los intentos fallidos por ip
    counts = fails.groupby('ip_origen')['tipo_mensaje'].count()

    # Acedemos con el for al contenido de ese groupby
    for ip, value in counts.items():
        # se crea esa tupla para almacenar por iteracion la pareja [ip, value] para hacerle un append a ip_suspicious 
        tuple = []
        if value >= umbral:
            tuple.append(ip)
            tuple.append(value)
            ip_suspicious.append(tuple)

    
    # con este for se accede las ip's sospechosas y en df original lo filtra por dichas ip's para generar un nuevo dataset
    for tuple in ip_suspicious:
        suspicious = df[df['ip_origen'] == tuple[0]] # 0 porque ahi esta la ip
        list_dataframe.append(suspicious)

    df_suspicious = pd.concat(list_dataframe) # concatenan los df por diferentes ip 
    
    return df_suspicious
    
