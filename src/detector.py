from parser import parse_log
import pandas as pd

path = "data/raw/auth.log"
df = parse_log(path)

# funcion para detectar posibles ataques de fuerza bruta
def brute_force(df, umbral = 5):
    
    ip_suspicious = [] #ip_suspicius es un lista de tuplas que va contener ip sospechosas >= al umbral
    list_dataframe=[] # lista para concatenar diferens dataframe por ip

    #filtramos el tipo de mensaje por intentos fallidos para ver si una ip lo repite muchas veces en muy poco tiempo
    fails = df[(df['message_type'] == 'Failed password')|(df['message_type'] ==  'Failed password for invalid user')]
    #con el groupby contamos los intentos fallidos por ip
    counts = fails.groupby('ip_origin')['message_type'].count()

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
        suspicious = df[df['ip_origin'] == tuple[0]] # 0 porque ahi esta la ip
        list_dataframe.append(suspicious)

    df_suspicious = pd.concat(list_dataframe) # concatenan los df por diferentes ip 
    #print(df_suspicious)
    return df_suspicious
    
def user_enumeration(df,umbral = 3):

    list_dataframe=[] #lista de dataframes para concat en uno solo

    df_user = df[df['user'].notna()] # filtra por no nulos
    groupby_enumeration = df_user.groupby('ip_origin')['user']

    for ip,user in groupby_enumeration:
        dict_ip = {} # se crea la lista para almacenar por ip  los usuarios e intentos por cada usaurio
        user_unique=user.unique() # nos quedamos con valores unicos para ver por cuantos usuarios intento

        if user_unique.size >= umbral:# si uso mas usuarios que el umbral establecido entra al if
            dict_ip[ip] = user_unique # guarda por ip los intentos de usuarios 

            #este for recorre la lista de usarios para poder filtar por cada uno con la ip 
            for users in user_unique:
                enumeration = df[(df['user'] == users)&(df['ip_origin']== ip)] 
                list_dataframe.append(enumeration) 

    #Crear un dataset con concatenandolos
    df_enumeration = pd.concat(list_dataframe)
    
    return df_enumeration   
            
       
    #print(list_user)
#print(brute_force(df))    
print(user_enumeration(df))   
#print(df.info())